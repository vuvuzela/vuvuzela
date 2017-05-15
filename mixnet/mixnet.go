// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
)

type Server struct {
	SigningKey     ed25519.PrivateKey
	ServerPosition int // position in chain, starting at 0
	NumServers     int
	NextServer     *vrpc.Client

	Laplace rand.Laplace

	AccessCounts chan AccessCount

	roundsMu sync.RWMutex
	rounds   map[uint32]*roundState
}

type AccessCount struct {
	Singles int64
	Doubles int64
}

type CoordinatorService struct {
	*Server
}

type ChainService struct {
	*Server
}

type roundState struct {
	mu                sync.Mutex
	settingsSignature []byte
	numIncoming       int
	incoming          [][]byte
	sharedKeys        []*[32]byte
	incomingIndex     []int
	replies           [][]byte
	closed            bool
	err               error

	onionPrivateKey *[32]byte
	onionPublicKey  *[32]byte
	nextServerKeys  []*[32]byte

	noise     [][]byte
	noiseDone chan struct{}
}

func (srv *Server) getRound(round uint32) (*roundState, error) {
	var ok bool
	var st *roundState

	srv.roundsMu.RLock()
	if srv.rounds == nil {
		ok = false
	} else {
		st, ok = srv.rounds[round]
	}
	srv.roundsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("round %d not found", round)
	}
	return st, nil
}

type NewRoundArgs struct {
	Round uint32
}

type NewRoundReply struct {
	OnionKey *[32]byte
}

func (srv *CoordinatorService) NewRound(args *NewRoundArgs, reply *NewRoundReply) error {
	log.WithFields(log.Fields{"rpc": "NewRound", "round": args.Round}).Info()

	srv.roundsMu.Lock()
	if srv.rounds == nil {
		srv.rounds = make(map[uint32]*roundState)
	}
	st := srv.rounds[args.Round]
	srv.roundsMu.Unlock()

	if st != nil {
		reply.OnionKey = st.onionPublicKey
		return nil
	}

	public, private, err := box.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return fmt.Errorf("box.GenerateKey error: %s", err)
	}

	st = &roundState{
		onionPublicKey:  public,
		onionPrivateKey: private,
	}

	srv.roundsMu.Lock()
	srv.rounds[args.Round] = st
	srv.roundsMu.Unlock()

	reply.OnionKey = public

	return nil
}

type RoundSettings struct {
	Round uint32
	// OnionKeys are the encryption keys in mixnet order.
	OnionKeys []*[32]byte
}

func (r *RoundSettings) Sign(key ed25519.PrivateKey) []byte {
	return ed25519.Sign(key, r.msg())
}

func (r *RoundSettings) Verify(key ed25519.PublicKey, sig []byte) bool {
	return ed25519.Verify(key, r.msg(), sig)
}

func (r *RoundSettings) msg() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("RoundSettings")
	binary.Write(buf, binary.BigEndian, r.Round)
	for _, key := range r.OnionKeys {
		buf.Write(key[:])
	}
	return buf.Bytes()
}

type SetRoundSettingsReply struct {
	// Signature on RoundSettings
	Signature []byte
}

// SetRoundSettings is an RPC used by the coordinator to set the
// parameters for a round. The RPC returns a signature of the round
// settings. Clients must verify this signature from each server
// before participating in the round. This prevents dishonest servers
// from tricking clients and other servers into using different keys
// or a different number of mailboxes in a round (which can lead to
// distinguishable noise).
func (srv *CoordinatorService) SetRoundSettings(settings *RoundSettings, reply *SetRoundSettingsReply) error {
	log.WithFields(log.Fields{"rpc": "SetRoundSettings", "round": settings.Round}).Info()

	st, err := srv.getRound(settings.Round)
	if err != nil {
		return err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.settingsSignature != nil {
		reply.Signature = st.settingsSignature
		// round settings have already been set
		return nil
	}

	if len(settings.OnionKeys) != srv.NumServers {
		return errors.New("bad round settings: want %d keys, got %d", srv.NumServers, len(settings.OnionKeys))
	}

	if !bytes.Equal(settings.OnionKeys[srv.ServerPosition][:], st.onionPublicKey[:]) {
		return errors.New("bad round settings: unexpected key at position %d", srv.ServerPosition)
	}

	st.settingsSignature = settings.Sign(srv.SigningKey)
	reply.Signature = st.settingsSignature

	if !srv.lastServer() {
		// Last server doesn't generate noise.
		st.nextServerKeys = settings.OnionKeys[srv.ServerPosition+1:]
		st.noiseDone = make(chan struct{})
		nonce := ForwardNonce(settings.Round)

		go func() {
			numFakeSingles := srv.Laplace.Uint32()
			numFakeDoubles := srv.Laplace.Uint32()
			numFakeDoubles += numFakeDoubles % 2 // ensure numFakeDoubles is even
			st.noise = make([][]byte, numFakeSingles+numFakeDoubles)

			FillWithFakeSingles(st.noise[:numFakeSingles], nonce, st.nextServerKeys)
			FillWithFakeDoubles(st.noise[numFakeSingles:], nonce, st.nextServerKeys)
			close(st.noiseDone)
		}()
	}

	return nil
}

type SetNumIncomingArgs struct {
	Round       uint32
	NumIncoming int
}

func (srv *ChainService) SetNumIncoming(args *SetNumIncomingArgs, _ *struct{}) error {
	st, err := srv.getRound(args.Round)
	if err != nil {
		return err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.numIncoming == 0 {
		st.numIncoming = args.NumIncoming
		st.incoming = make([][]byte, args.NumIncoming)
		st.sharedKeys = make([]*[32]byte, args.NumIncoming)
		return nil
	}
	if st.numIncoming == args.NumIncoming {
		// already set correctly
		return nil
	}

	return fmt.Errorf("round %d: numIncoming already set to %d", args.Round, args.NumIncoming)
}

type AddArgs struct {
	Round  uint32
	Offset int
	Onions [][]byte
}

// Add is an RPC used to add onions to the mix.
func (srv *ChainService) Add(args *AddArgs, _ *struct{}) error {
	log.WithFields(log.Fields{"rpc": "Add", "round": args.Round, "onions": len(args.Onions)}).Debug()

	st, err := srv.getRound(args.Round)
	if err != nil {
		return err
	}

	st.mu.Lock()
	numIncoming := st.numIncoming
	st.mu.Unlock()
	if numIncoming == 0 {
		return fmt.Errorf("did not set numIncoming")
	}
	if args.Offset+len(args.Onions) > numIncoming {
		return fmt.Errorf("overflowing onions (offset=%d, onions=%d, incoming=%d)", args.Offset, len(args.Onions), st.numIncoming)
	}

	nonce := ForwardNonce(args.Round)
	expectedOnionSize := (srv.NumServers-srv.ServerPosition)*onionbox.Overhead + sizeMixMessage

	for i, onion := range args.Onions {
		if len(onion) == expectedOnionSize {
			var theirPublic [32]byte
			copy(theirPublic[:], onion[0:32])

			sharedKey := new([32]byte)
			box.Precompute(sharedKey, &theirPublic, st.onionPrivateKey)

			message, ok := box.OpenAfterPrecomputation(nil, onion[32:], nonce, sharedKey)
			if ok {
				j := args.Offset + i
				st.mu.Lock()
				if !st.closed {
					st.incoming[j] = message
					st.sharedKeys[j] = sharedKey
					st.mu.Unlock()
				} else {
					st.mu.Unlock()
					return errors.New("round %d closed", args.Round)
				}
			} else {
				log.WithFields(log.Fields{"rpc": "Add", "round": args.Round}).Error("Decrypting onion failed")
			}
		}
	}

	return err
}

func (srv *Server) filterIncoming(st *roundState) {
	incomingValid := make([][]byte, 0, len(st.incoming))
	incomingIndex := make([]int, len(st.incoming))

	seen := make(map[uint64]bool)
	for i, msg := range st.incoming {
		if msg == nil {
			incomingIndex[i] = -1
			continue
		}
		// last 8 bytes because key is at the beginning
		msgkey := binary.BigEndian.Uint64(msg[len(msg)-8:])
		if seen[msgkey] {
			incomingIndex[i] = -1
		} else {
			seen[msgkey] = true
			incomingIndex[i] = len(incomingValid)
			incomingValid = append(incomingValid, msg)
		}
	}

	st.incoming = incomingValid
	st.incomingIndex = incomingIndex
}

func (srv *ChainService) Close(round uint32, _ *struct{}) error {
	log.WithFields(log.Fields{"rpc": "Close", "round": round}).Info()

	st, err := srv.getRound(round)
	if err != nil {
		return err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return st.err
	}
	st.closed = true

	log.WithFields(log.Fields{
		"rpc":    "Close",
		"round":  round,
		"onions": len(st.incoming),
	}).Info()

	srv.filterIncoming(st)

	if !srv.lastServer() {
		<-st.noiseDone
		numNonNoise := len(st.incoming)
		outgoing := append(st.incoming, st.noise...)
		st.noise = nil
		st.incoming = nil

		shuffler := shuffle.New(rand.Reader, len(outgoing))
		shuffler.Shuffle(outgoing)

		replies, err := RunRound(srv.NextServer, round, outgoing)
		if err != nil {
			return errors.New("RunRound: %s", err)
		}

		shuffler.Unshuffle(replies)
		// drop the noise
		st.replies = replies[:numNonNoise]
	} else {
		var singles, doubles int64
		var dest DeadDrop
		deadDrops := make(map[DeadDrop][]int)
		for i, msg := range st.incoming {
			copy(dest[:], msg[0:16])
			switch len(deadDrops[dest]) {
			case 0:
				singles++
				deadDrops[dest] = append(deadDrops[dest], i)
			case 1:
				singles--
				doubles++
				deadDrops[dest] = append(deadDrops[dest], i)
			}
		}

		st.replies = make([][]byte, len(st.incoming))
		concurrency.ParallelFor(len(st.replies), func(p *concurrency.P) {
			var dest DeadDrop
			var other int
			for i, ok := p.Next(); ok; i, ok = p.Next() {
				msg := st.incoming[i]
				copy(dest[:], msg[0:16])
				drop := deadDrops[dest]
				if len(drop) == 1 {
					st.replies[i] = msg[16 : 16+SizeEncryptedMessageBody]
				}
				if len(drop) == 2 {
					if i == drop[0] {
						other = drop[1]
					} else {
						other = drop[0]
					}
					st.replies[i] = st.incoming[other][16 : 16+SizeEncryptedMessageBody]
				}
			}
		})

		st.incoming = nil

		counts := AccessCount{
			Singles: singles,
			Doubles: doubles,
		}
		select {
		case srv.AccessCounts <- counts:
		default:
		}
	}

	return nil
}

func (srv *Server) lastServer() bool {
	return srv.ServerPosition == srv.NumServers-1
}

type GetArgs struct {
	Round  uint32
	Offset int
	Count  int
}

type GetReply struct {
	Onions [][]byte
}

func (srv *ChainService) Get(args *GetArgs, reply *GetReply) error {
	log.WithFields(log.Fields{"rpc": "Get", "round": args.Round, "offset": args.Offset}).Debug()

	st, err := srv.getRound(args.Round)
	if err != nil {
		return err
	}

	st.mu.Lock()
	closed := st.closed
	st.mu.Unlock()
	if !closed {
		return errors.New("round not closed")
	}

	nonce := BackwardNonce(args.Round)

	reply.Onions = make([][]byte, args.Count)
	for i := range reply.Onions {
		j := args.Offset + i

		var msg []byte
		var key *[32]byte
		if v := st.incomingIndex[j]; v > -1 {
			msg = st.replies[v]
			key = st.sharedKeys[j]
		} else {
			msg = make([]byte, SizeEncryptedMessageBody)
			key = new([32]byte)
			rand.Read(key[:])
		}

		reply.Onions[i] = box.SealAfterPrecomputation(nil, msg, nonce, key)
	}

	return nil
}

func (srv *ChainService) Delete(round uint32, _ *struct{}) error {
	log.WithFields(log.Fields{"rpc": "Delete", "round": round}).Info()

	srv.roundsMu.Lock()
	delete(srv.rounds, round)
	srv.roundsMu.Unlock()
	return nil
}

// NewRound starts a new mixing round on the given servers.
// NewRound fills in settings.OnionKeys and returns the servers'
// signatures of the round settings.
//
// settings.Round and settings.NumMailboxes must be set.
func NewRound(servers []*vrpc.Client, settings *RoundSettings) ([][]byte, error) {
	settings.OnionKeys = make([]*[32]byte, len(servers))

	for i, server := range servers {
		args := &NewRoundArgs{Round: settings.Round}
		reply := new(NewRoundReply)
		if err := server.Call("Coordinator.NewRound", args, reply); err != nil {
			return nil, fmt.Errorf("server %s: %s", server.Address, err)
		}
		settings.OnionKeys[i] = reply.OnionKey
	}

	signatures := make([][]byte, len(servers))
	for i, server := range servers {
		reply := new(SetRoundSettingsReply)
		if err := server.Call("Coordinator.SetRoundSettings", settings, reply); err != nil {
			return signatures, fmt.Errorf("server %s: %s", server.Address, err)
		}
		signatures[i] = reply.Signature
	}
	return signatures, nil
}

func RunRound(server *vrpc.Client, round uint32, onions [][]byte) ([][]byte, error) {
	err := server.Call("Chain.SetNumIncoming", &SetNumIncomingArgs{
		Round:       round,
		NumIncoming: len(onions),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("SetNumIncoming: %s", err)
	}

	spans := concurrency.Spans(len(onions), 4000)
	calls := make([]*vrpc.Call, len(spans))

	for i := range calls {
		span := spans[i]
		calls[i] = &vrpc.Call{
			Method: "Chain.Add",
			Args: &AddArgs{
				Round:  round,
				Offset: span.Start,
				Onions: onions[span.Start : span.Start+span.Count],
			},
			Reply: nil,
		}
	}

	if err := server.CallMany(calls); err != nil {
		return nil, fmt.Errorf("Add: %s", err)
	}

	if err := server.Call("Chain.Close", round, nil); err != nil {
		return nil, fmt.Errorf("Close: %s", err)
	}

	for i := range calls {
		span := spans[i]
		calls[i] = &vrpc.Call{
			Method: "Chain.Get",
			Args: &GetArgs{
				Round:  round,
				Offset: span.Start,
				Count:  span.Count,
			},
			Reply: new(GetReply),
		}
	}

	if err := server.CallMany(calls); err != nil {
		return nil, fmt.Errorf("Get: %s", err)
	}

	replies := make([][]byte, len(onions))
	concurrency.ParallelFor(len(calls), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			span := spans[i]
			copy(replies[span.Start:span.Start+span.Count], calls[i].Reply.(*GetReply).Onions)
		}
	})

	err = server.Call("Chain.Delete", round, nil)

	return replies, err
}

func ForwardNonce(round uint32) *[24]byte {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[0:4], round)
	nonce[4] = 0
	return &nonce
}

func BackwardNonce(round uint32) *[24]byte {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[0:4], round)
	nonce[4] = 1
	return &nonce
}
