package vuvuzela

import (
	"encoding/binary"
	"fmt"
	"sync"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"

	. "github.com/davidlazar/vuvuzela/internal"
	"github.com/davidlazar/vuvuzela/vrpc"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
)

type DialService struct {
	roundsMu sync.RWMutex
	rounds   map[uint32]*DialRound

	Idle *sync.Mutex

	LaplaceMu float64
	LaplaceB  float64

	PKI        *PKI
	ServerName string
	PrivateKey *BoxKey
	Client     *vrpc.Client
	LastServer bool
}

type DialRound struct {
	sync.Mutex

	status   dialStatus
	incoming [][]byte

	noise   [][]byte
	noiseWg sync.WaitGroup
}

type dialStatus int

const (
	dialRoundOpen dialStatus = iota + 1
	dialRoundClosed
)

func InitDialService(srv *DialService) {
	srv.rounds = make(map[uint32]*DialRound)
}

func (srv *DialService) getRound(round uint32, expectedStatus dialStatus) (*DialRound, error) {
	srv.roundsMu.RLock()
	r, ok := srv.rounds[round]
	srv.roundsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("round %d not found", round)
	}
	if r.status != expectedStatus {
		return r, fmt.Errorf("round %d: status %v, expecting %v", round, r.status, expectedStatus)
	}
	return r, nil
}

func (srv *DialService) NewRound(Round uint32, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "dial", "rpc": "NewRound", "round": Round}).Info()
	srv.Idle.Lock()

	srv.roundsMu.Lock()
	defer srv.roundsMu.Unlock()

	_, exists := srv.rounds[Round]
	if exists {
		return fmt.Errorf("round %d already exists", Round)
	}

	round := &DialRound{}
	srv.rounds[Round] = round

	round.noiseWg.Add(1)
	go func() {
		// NOTE: unlike the convo protocol, the last server also adds noise
		noiseTotal := 0
		noiseCounts := make([]int, TotalDialBuckets+1)
		for b := range noiseCounts {
			bmu := cappedFlooredLaplace(srv.LaplaceMu, srv.LaplaceB)
			noiseCounts[b] = bmu
			noiseTotal += bmu
		}
		round.noise = make([][]byte, noiseTotal)

		nonce := ForwardNonce(Round)
		nextKeys := srv.PKI.NextServerKeys(srv.ServerName).Keys()

		FillWithFakeIntroductions(round.noise, noiseCounts, nonce, nextKeys)
		round.noiseWg.Done()
	}()

	round.status = dialRoundOpen
	return nil
}

type DialAddArgs struct {
	Round  uint32
	Onions [][]byte
}

func (srv *DialService) Add(args *DialAddArgs, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "dial", "rpc": "Add", "round": args.Round, "onions": len(args.Onions)}).Debug()

	round, err := srv.getRound(args.Round, dialRoundOpen)
	if err != nil {
		return err
	}

	nonce := ForwardNonce(args.Round)
	messages := make([][]byte, 0, len(args.Onions))
	expectedOnionSize := srv.PKI.IncomingOnionOverhead(srv.ServerName) + SizeDialExchange

	for _, onion := range args.Onions {
		if len(onion) == expectedOnionSize {
			var theirPublic [32]byte
			copy(theirPublic[:], onion[0:32])

			message, ok := box.Open(nil, onion[32:], nonce, &theirPublic, srv.PrivateKey.Key())
			if ok {
				messages = append(messages, message)
			}
		}
	}

	round.Lock()
	round.incoming = append(round.incoming, messages...)
	round.Unlock()

	return nil
}

func (srv *DialService) filterIncoming(round *DialRound) {
	incomingValid := make([][]byte, 0, len(round.incoming))

	seen := make(map[uint64]bool)
	for _, msg := range round.incoming {
		msgkey := binary.BigEndian.Uint64(msg[len(msg)-8:])
		if !seen[msgkey] {
			seen[msgkey] = true
			incomingValid = append(incomingValid, msg)
		}
	}

	round.incoming = incomingValid
}

func (srv *DialService) Close(Round uint32, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "dial", "rpc": "Close", "round": Round}).Info()

	round, err := srv.getRound(Round, dialRoundOpen)
	if err != nil {
		return err
	}

	srv.filterIncoming(round)

	round.noiseWg.Wait()
	round.incoming = append(round.incoming, round.noise...)

	shuffler := shuffle.New(rand.Reader, len(round.incoming))
	shuffler.Shuffle(round.incoming)

	if !srv.LastServer {
		if err := NewDialRound(srv.Client, Round); err != nil {
			return fmt.Errorf("NewDialRound: %s", err)
		}
		srv.Idle.Unlock()

		if err := RunDialRound(srv.Client, Round, round.incoming); err != nil {
			return fmt.Errorf("RunDialRound: %s", err)
		}
		round.incoming = nil
	} else {
		srv.Idle.Unlock()
	}
	round.noise = nil

	round.status = dialRoundClosed
	return nil
}

type DialBucketsArgs struct {
	Round uint32
}

type DialBucketsResult struct {
	Buckets [][][SizeEncryptedIntro]byte
}

func (srv *DialService) Buckets(args *DialBucketsArgs, result *DialBucketsResult) error {
	log.WithFields(log.Fields{"service": "dial", "rpc": "Buckets", "round": args.Round}).Info()

	if !srv.LastServer {
		return fmt.Errorf("Dial.Buckets can only be called on the last server")
	}

	round, err := srv.getRound(args.Round, dialRoundClosed)
	if err != nil {
		return err
	}

	buckets := make([][][SizeEncryptedIntro]byte, TotalDialBuckets)

	ex := new(DialExchange)
	for _, m := range round.incoming {
		if len(m) != SizeDialExchange {
			continue
		}
		if err := ex.Unmarshal(m); err != nil {
			continue
		}
		if ex.Bucket == 0 {
			continue // dummy dead drop
		}
		if ex.Bucket-1 >= uint32(len(buckets)) {
			continue
		}
		buckets[ex.Bucket-1] = append(buckets[ex.Bucket-1], ex.EncryptedIntro)
	}

	result.Buckets = buckets
	return nil
}

// TODO we should probably have a corresponding Delete rpc

func NewDialRound(client *vrpc.Client, round uint32) error {
	return client.Call("DialService.NewRound", round, nil)
}

func RunDialRound(client *vrpc.Client, round uint32, onions [][]byte) error {
	spans := Spans(len(onions), 4000)
	calls := make([]*vrpc.Call, len(spans))

	ParallelFor(len(calls), func(p *P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			span := spans[i]
			calls[i] = &vrpc.Call{
				Method: "DialService.Add",
				Args: &DialAddArgs{
					Round:  round,
					Onions: onions[span.Start : span.Start+span.Count],
				},
				Reply: nil,
			}
		}
	})

	if err := client.CallMany(calls); err != nil {
		return fmt.Errorf("Add: %s", err)
	}

	if err := client.Call("DialService.Close", round, nil); err != nil {
		return fmt.Errorf("Close: %s", err)
	}

	return nil
}
