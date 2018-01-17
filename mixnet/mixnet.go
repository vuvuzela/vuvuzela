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
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
	pb "vuvuzela.io/vuvuzela/mixnet/convopb"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson mixnet.go

type MixService interface {
	SizeIncomingMessage() int
	SizeReplyMessage() int

	GenerateNoise(round uint32, nextServerKeys []*[32]byte) [][]byte

	// SortReplies is called by the last server in the chain to sort incoming
	// messages into replies sent back through the chain. Assumes:
	//   len(replies) = len(incoming);
	//   len(incoming[i]) = SizeIncomingMessage();
	//   len(replies[i]) = SizeReplyMessage();
	SortReplies(incoming [][]byte) (replies [][]byte)
}

type Server struct {
	SigningKey     ed25519.PrivateKey
	CoordinatorKey ed25519.PublicKey

	Services map[string]MixService

	Laplace rand.Laplace

	roundsMu sync.RWMutex
	rounds   map[serviceRound]*roundState

	once      sync.Once
	mixClient *Client
}

type serviceRound struct {
	Service string
	Round   uint32
}

type roundState struct {
	mu                sync.Mutex
	settingsSignature []byte
	numIncoming       uint32
	incoming          [][]byte
	sharedKeys        []*[32]byte
	incomingIndex     []int
	replies           [][]byte
	closed            bool
	err               error

	chain           []PublicServerConfig
	myPos           int
	onionPrivateKey *[32]byte
	onionPublicKey  *[32]byte
	nextServerKeys  []*[32]byte

	noise     [][]byte
	noiseDone chan struct{}
}

//easyjson:readable
type PublicServerConfig struct {
	Key     ed25519.PublicKey
	Address string
}

func (c PublicServerConfig) Proto() *pb.PublicServerConfig {
	return &pb.PublicServerConfig{
		Key:     c.Key,
		Address: c.Address,
	}
}

func (c *PublicServerConfig) FromProto(pbc *pb.PublicServerConfig) error {
	if len(pbc.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key in PublicServerConfig protobuf: %#v", pbc.Key)
	}
	c.Key = pbc.Key
	c.Address = pbc.Address
	return nil
}

func (srv *Server) getRound(service string, round uint32) (*roundState, error) {
	var ok bool
	var st *roundState

	srv.roundsMu.RLock()
	if srv.rounds == nil {
		ok = false
	} else {
		st, ok = srv.rounds[serviceRound{service, round}]
	}
	srv.roundsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("round %d not found", round)
	}
	return st, nil
}

func (srv *Server) auth(ctx context.Context, expectedKey ed25519.PublicKey) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Errorf(codes.DataLoss, "failed to get peer from ctx")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "unknown AuthInfo type: %s", p.AuthInfo.AuthType())
	}

	certs := tlsInfo.State.PeerCertificates
	if len(certs) != 1 {
		status.Errorf(codes.Unauthenticated, "expecting 1 peer certificate, got %d", len(certs))
	}
	peerKey := edtls.GetSigningKey(certs[0])

	if !bytes.Equal(expectedKey, peerKey) {
		return status.Errorf(codes.Unauthenticated, "wrong edtls key")
	}

	return nil
}

// authPrev is used to limit an RPC to the "previous" server in the chain.
func (srv *Server) authPrev(ctx context.Context, st *roundState) error {
	var expectedKey ed25519.PublicKey
	if st.myPos == 0 {
		expectedKey = srv.CoordinatorKey
	} else {
		expectedKey = st.chain[st.myPos-1].Key
	}
	return srv.auth(ctx, expectedKey)
}

func (srv *Server) NewRound(ctx context.Context, req *pb.NewRoundRequest) (*pb.NewRoundResponse, error) {
	if err := srv.auth(ctx, srv.CoordinatorKey); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"rpc": "NewRound", "round": req.Round}).Info()

	srv.roundsMu.Lock()
	if srv.rounds == nil {
		srv.rounds = make(map[serviceRound]*roundState)
	}
	st := srv.rounds[serviceRound{req.Service, req.Round}]
	srv.roundsMu.Unlock()

	if st != nil {
		return &pb.NewRoundResponse{
			OnionKey: st.onionPublicKey[:],
		}, nil
	}

	public, private, err := box.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return nil, fmt.Errorf("box.GenerateKey error: %s", err)
	}

	chain := make([]PublicServerConfig, len(req.Chain))
	myPos := -1
	myPub := srv.SigningKey.Public().(ed25519.PublicKey)
	for i, conf := range req.Chain {
		if err := chain[i].FromProto(conf); err != nil {
			return nil, err
		}
		if bytes.Equal(conf.Key, myPub) {
			myPos = i
		}
	}
	if myPos == -1 {
		return nil, errors.New("my key is not in the chain")
	}

	st = &roundState{
		chain:           chain,
		myPos:           myPos,
		onionPublicKey:  public,
		onionPrivateKey: private,
	}

	srv.roundsMu.Lock()
	srv.rounds[serviceRound{req.Service, req.Round}] = st
	srv.roundsMu.Unlock()

	return &pb.NewRoundResponse{
		OnionKey: public[:],
	}, nil
}

// SetRoundSettings is an RPC used by the coordinator to set the
// parameters for a round. The RPC returns a signature of the round
// settings. Clients must verify this signature from each server
// before participating in the round. This prevents dishonest servers
// from tricking clients and other servers into using different keys
// or a different number of mailboxes in a round (which can lead to
// distinguishable noise).
func (srv *Server) SetRoundSettings(ctx context.Context, req *pb.SetRoundSettingsRequest) (*pb.RoundSettingsSignature, error) {
	if err := srv.auth(ctx, srv.CoordinatorKey); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"rpc": "SetRoundSettings", "service": req.Settings.Service, "round": req.Settings.Round}).Info()

	var settings RoundSettings
	err := settings.FromProto(req.Settings)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid round settings: %s", err)
	}

	st, err := srv.getRound(settings.Service, settings.Round)
	if err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.settingsSignature != nil {
		// round settings have already been set
		return &pb.RoundSettingsSignature{
			Signature: st.settingsSignature,
		}, nil
	}

	if len(settings.OnionKeys) != len(st.chain) {
		return nil, errors.New("bad round settings: want %d keys, got %d", len(st.chain), len(settings.OnionKeys))
	}

	if !bytes.Equal(settings.OnionKeys[st.myPos][:], st.onionPublicKey[:]) {
		return nil, errors.New("bad round settings: unexpected key at position %d", st.myPos)
	}

	sig := ed25519.Sign(srv.SigningKey, settings.SigningMessage())
	st.settingsSignature = sig

	if st.myPos < len(st.chain)-1 {
		// Last server doesn't generate noise.
		service, ok := srv.Services[settings.Service]
		if !ok {
			return nil, errors.New("unknown service: %q", settings.Service)
		}
		st.nextServerKeys = settings.OnionKeys[st.myPos+1:]
		st.noiseDone = make(chan struct{})

		go func() {
			st.noise = service.GenerateNoise(settings.Round, st.nextServerKeys)
			close(st.noiseDone)
		}()
	}

	return &pb.RoundSettingsSignature{
		Signature: sig,
	}, nil
}

func (srv *Server) SetNumIncoming(ctx context.Context, req *pb.SetNumIncomingRequest) (*pb.Nothing, error) {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}
	if err := srv.authPrev(ctx, st); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.numIncoming == 0 {
		st.numIncoming = req.NumIncoming
		st.incoming = make([][]byte, req.NumIncoming)
		st.sharedKeys = make([]*[32]byte, req.NumIncoming)
		return &pb.Nothing{}, nil
	}
	if st.numIncoming == req.NumIncoming {
		// already set correctly
		return &pb.Nothing{}, nil
	}

	return nil, fmt.Errorf("round %d: numIncoming already set to %d", req.Round, req.NumIncoming)
}

// Add is an RPC used to add onions to the mix.
func (srv *Server) AddOnions(ctx context.Context, req *pb.AddOnionsRequest) (*pb.Nothing, error) {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}
	if err := srv.authPrev(ctx, st); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"rpc": "AddOnions", "round": req.Round, "onions": len(req.Onions)}).Debug()

	st.mu.Lock()
	numIncoming := st.numIncoming
	st.mu.Unlock()
	if numIncoming == 0 {
		return nil, fmt.Errorf("did not set numIncoming")
	}
	if req.Offset+uint32(len(req.Onions)) > numIncoming {
		return nil, fmt.Errorf("overflowing onions (offset=%d, onions=%d, incoming=%d)", req.Offset, len(req.Onions), st.numIncoming)
	}

	service := srv.Services[req.Service]
	nonce := ForwardNonce(req.Round)
	expectedOnionSize := (len(st.chain)-st.myPos)*onionbox.Overhead + service.SizeIncomingMessage()

	messages := make([][]byte, len(req.Onions))
	sharedKeys := make([]*[32]byte, len(req.Onions))
	for i, onion := range req.Onions {
		if len(onion) == expectedOnionSize {
			var theirPublic [32]byte
			copy(theirPublic[:], onion[0:32])

			sharedKey := new([32]byte)
			box.Precompute(sharedKey, &theirPublic, st.onionPrivateKey)

			message, ok := box.OpenAfterPrecomputation(nil, onion[32:], nonce, sharedKey)
			if ok {
				messages[i] = message
				sharedKeys[i] = sharedKey
			} else {
				log.WithFields(log.Fields{"rpc": "AddOnions", "round": req.Round}).Error("Decrypting onion failed")
			}
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return nil, errors.New("round %d closed", req.Round)
	}
	for i := range messages {
		j := req.Offset + uint32(i)
		st.incoming[j] = messages[i]
		st.sharedKeys[j] = sharedKeys[i]
	}

	return &pb.Nothing{}, nil
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

func (srv *Server) CloseRound(ctx context.Context, req *pb.CloseRoundRequest) (*pb.Nothing, error) {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}
	if err := srv.authPrev(ctx, st); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return &pb.Nothing{}, st.err
	}
	st.closed = true

	logger := log.WithFields(log.Fields{
		"rpc":    "CloseRound",
		"round":  req.Round,
		"onions": len(st.incoming),
	})

	srv.filterIncoming(st)

	// if not last server
	if st.myPos < len(st.chain)-1 {
		start := time.Now()
		<-st.noiseDone
		numNonNoise := len(st.incoming)
		outgoing := append(st.incoming, st.noise...)
		st.noise = nil
		st.incoming = nil

		shuffler := shuffle.New(rand.Reader, len(outgoing))
		shuffler.Shuffle(outgoing)

		srv.once.Do(func() {
			srv.mixClient = &Client{
				Key: srv.SigningKey,
			}
		})
		replies, err := srv.mixClient.RunRound(ctx, st.chain[st.myPos+1], req.Service, req.Round, outgoing)
		if err != nil {
			return nil, errors.New("RunRound: %s", err)
		}

		shuffler.Unshuffle(replies)
		// drop the noise
		st.replies = replies[:numNonNoise]
		duration := time.Now().Sub(start)
		logger.WithFields(log.Fields{"duration": duration}).Infof("Ready to return onions")
	} else {
		start := time.Now()
		st.replies = srv.Services[req.Service].SortReplies(st.incoming)
		duration := time.Now().Sub(start)
		logger.WithFields(log.Fields{"duration": duration}).Infof("Sorted replies")

		st.incoming = nil
	}

	return &pb.Nothing{}, nil
}

func (srv *Server) GetOnions(ctx context.Context, req *pb.GetOnionsRequest) (*pb.GetOnionsResponse, error) {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}
	if err := srv.authPrev(ctx, st); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"rpc": "Get", "round": req.Round, "offset": req.Offset}).Debug()

	st.mu.Lock()
	closed := st.closed
	st.mu.Unlock()
	if !closed {
		return nil, errors.New("round not closed")
	}

	nonce := BackwardNonce(req.Round)

	replyMsgSize := srv.Services[req.Service].SizeReplyMessage()
	replies := make([][]byte, req.Count)
	for i := range replies {
		j := req.Offset + uint32(i)

		var msg []byte
		var key *[32]byte
		if v := st.incomingIndex[j]; v > -1 {
			msg = st.replies[v]
			key = st.sharedKeys[j]
		} else {
			msg = make([]byte, replyMsgSize)
			key = new([32]byte)
			rand.Read(key[:])
		}

		replies[i] = box.SealAfterPrecomputation(nil, msg, nonce, key)
	}

	return &pb.GetOnionsResponse{
		Onions: replies,
	}, nil
}

func (srv *Server) DeleteRound(ctx context.Context, req *pb.DeleteRoundRequest) (*pb.Nothing, error) {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}
	if err := srv.authPrev(ctx, st); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"rpc": "DeleteRound", "round": req.Round}).Info()

	srv.roundsMu.Lock()
	delete(srv.rounds, serviceRound{req.Service, req.Round})
	srv.roundsMu.Unlock()
	return nil, nil
}

type Client struct {
	Key ed25519.PrivateKey

	mu    sync.Mutex
	conns map[[ed25519.PublicKeySize]byte]*grpc.ClientConn
}

func (c *Client) getConn(server PublicServerConfig) (pb.MixnetClient, error) {
	var k [ed25519.PublicKeySize]byte
	copy(k[:], server.Key)

	c.mu.Lock()
	if c.conns == nil {
		c.conns = make(map[[ed25519.PublicKeySize]byte]*grpc.ClientConn)
	}
	cc := c.conns[k]
	c.mu.Unlock()

	if cc == nil {
		creds := credentials.NewTLS(edtls.NewTLSClientConfig(c.Key, server.Key))

		var err error
		cc, err = grpc.Dial(server.Address, grpc.WithTransportCredentials(creds))
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.conns[k] = cc
		c.mu.Unlock()
	}

	return pb.NewMixnetClient(cc), nil
}

// NewRound starts a new mixing round on the given servers.
// NewRound fills in settings.OnionKeys and returns the servers'
// signatures of the round settings.
//
// settings.Round must be set.
func (c *Client) NewRound(ctx context.Context, servers []PublicServerConfig, settings *RoundSettings) ([][]byte, error) {
	settings.OnionKeys = make([]*[32]byte, len(servers))

	chain := make([]*pb.PublicServerConfig, len(servers))
	for i, conf := range servers {
		chain[i] = conf.Proto()
	}
	newRoundReq := &pb.NewRoundRequest{
		Service: settings.Service,
		Round:   settings.Round,
		Chain:   chain,
	}

	conns := make([]pb.MixnetClient, len(servers))
	for i, server := range servers {
		conn, err := c.getConn(server)
		if err != nil {
			return nil, err
		}
		conns[i] = conn
	}

	for i, server := range servers {
		response, err := conns[i].NewRound(ctx, newRoundReq)
		if err != nil {
			return nil, errors.Wrap(err, "server %s: NewRound", server.Address)
		}
		key := new([32]byte)
		copy(key[:], response.OnionKey[:])
		settings.OnionKeys[i] = key
	}

	setSettingsReq := &pb.SetRoundSettingsRequest{
		Settings: settings.Proto(),
	}
	signatures := make([][]byte, len(servers))
	for i, server := range servers {
		response, err := conns[i].SetRoundSettings(ctx, setSettingsReq)
		if err != nil {
			return signatures, errors.Wrap(err, "server %s: SetRoundSettings", server.Address)
		}
		signatures[i] = response.Signature
	}
	return signatures, nil
}

func (c *Client) RunRound(ctx context.Context, server PublicServerConfig, service string, round uint32, onions [][]byte) ([][]byte, error) {
	conn, err := c.getConn(server)
	if err != nil {
		return nil, err
	}

	_, err = conn.SetNumIncoming(ctx, &pb.SetNumIncomingRequest{
		Service:     service,
		Round:       round,
		NumIncoming: uint32(len(onions)),
	})
	if err != nil {
		return nil, err
	}

	start := time.Now()
	errs := make(chan error, 1)
	spans := concurrency.Spans(len(onions), 4000)
	for _, span := range spans {
		go func(span concurrency.Span) {
			req := &pb.AddOnionsRequest{
				Service: service,
				Round:   round,
				Offset:  uint32(span.Start),
				Onions:  onions[span.Start : span.Start+span.Count],
			}
			_, err := conn.AddOnions(ctx, req)
			errs <- err
		}(span)
	}

	var addErr error
	for i := 0; i < len(spans); i++ {
		err := <-errs
		if addErr == nil && err != nil {
			addErr = err
		}
	}
	if addErr != nil {
		return nil, addErr
	}
	duration := time.Now().Sub(start)
	log.WithFields(log.Fields{"round": round, "duration": duration, "onions": len(onions)}).Infof("RunRound: added onions to next mixer")

	closeReq := &pb.CloseRoundRequest{
		Service: service,
		Round:   round,
	}
	_, closeErr := conn.CloseRound(ctx, closeReq)
	if closeErr != nil {
		return nil, closeErr
	}

	start = time.Now()
	replies := make([][]byte, len(onions))
	for _, span := range spans {
		go func(span concurrency.Span) {
			req := &pb.GetOnionsRequest{
				Service: service,
				Round:   round,
				Offset:  uint32(span.Start),
				Count:   uint32(span.Count),
			}
			resp, err := conn.GetOnions(ctx, req)
			if err == nil {
				copy(replies[span.Start:span.Start+span.Count], resp.Onions)
			}
			errs <- err
		}(span)
	}

	var getErr error
	for i := 0; i < len(spans); i++ {
		err := <-errs
		if getErr == nil && err != nil {
			getErr = err
		}
	}
	if getErr != nil {
		return nil, getErr
	}
	duration = time.Now().Sub(start)
	log.WithFields(log.Fields{"round": round, "duration": duration, "onions": len(onions)}).Infof("RunRound: fetched onions from prev mixer")

	_, err = conn.DeleteRound(ctx, &pb.DeleteRoundRequest{
		Service: service,
		Round:   round,
	})
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
