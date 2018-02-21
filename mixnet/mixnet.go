// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
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

	once           sync.Once
	mixClient      *Client
	decryptionJobs chan decryptionJob
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
	sharedKeys        [][32]byte
	incomingIndex     []int
	replies           [][]byte
	acceptingOnions   bool
	decryptWg         sync.WaitGroup
	encryptDone       chan struct{}
	closed            bool
	err               error

	chain             []PublicServerConfig
	myPos             int
	incomingOnionSize int
	onionPrivateKey   *[32]byte
	onionPublicKey    *[32]byte
	nextServerKeys    []*[32]byte

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

	srv.once.Do(func() {
		srv.mixClient = &Client{
			Key: srv.SigningKey,
		}

		workers := runtime.NumCPU() * 2
		srv.decryptionJobs = make(chan decryptionJob, workers)
		for i := 0; i < workers; i++ {
			go decryptionWorker(srv.decryptionJobs)
		}
	})

	log.WithFields(log.Fields{"rpc": "NewRound", "round": req.Round}).Info()
	service, ok := srv.Services[req.Service]
	if !ok {
		return nil, errors.New("unknown service: %q", req.Service)
	}

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
		encryptDone: make(chan struct{}),

		chain:             chain,
		myPos:             myPos,
		incomingOnionSize: (len(chain)-myPos)*onionbox.Overhead + service.SizeIncomingMessage(),
		onionPublicKey:    public,
		onionPrivateKey:   private,
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
		st.acceptingOnions = true
		st.numIncoming = req.NumIncoming
		st.incoming = make([][]byte, req.NumIncoming)
		// Allocate all the shared keys upfront.
		st.sharedKeys = make([][32]byte, req.NumIncoming)
		return &pb.Nothing{}, nil
	}
	if st.numIncoming == req.NumIncoming {
		// already set correctly
		return &pb.Nothing{}, nil
	}

	return nil, fmt.Errorf("round %d: numIncoming already set to %d", req.Round, req.NumIncoming)
}

type decryptionJob struct {
	st    *roundState
	round uint32
	req   *pb.AddOnionsRequest
}

func decryptionWorker(in chan decryptionJob) {
	var theirPublic [32]byte
	for job := range in {
		st := job.st
		nonce := ForwardNonce(job.round)
		offset := int(job.req.Offset)
		expectedSize := st.incomingOnionSize
		for i, onion := range job.req.Onions {
			if len(onion) != expectedSize {
				log.Infof("onion is unexpected size: got %d, want %d", len(onion), expectedSize)
				continue
			}

			copy(theirPublic[:], onion[0:32])
			box.Precompute(&st.sharedKeys[offset+i], &theirPublic, st.onionPrivateKey)

			// TODO we could avoid allocating here, but is it worth it?
			msg, ok := box.OpenAfterPrecomputation(nil, onion[32:], nonce, &st.sharedKeys[offset+i])
			st.incoming[offset+i] = msg
			if !ok {
				log.WithFields(log.Fields{"rpc": "AddOnions", "round": job.round}).Error("Decrypting onion failed")
			}
		}

		st.decryptWg.Done()
	}
}

type streamMetadata struct {
	service string
	round   uint32
}

func parseMetadata(ctx context.Context) (*streamMetadata, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("no metadata provided")
	}

	if md["service"] == nil {
		return nil, errors.New("missing service in metadata")
	}
	service := md["service"][0]

	if md["round"] == nil {
		return nil, errors.New("missing round in metadata")
	}

	r, err := strconv.ParseUint(md["round"][0], 10, 32)
	if err != nil {
		return nil, errors.New("invalid round: %q", md["round"][0])
	}

	return &streamMetadata{
		service: service,
		round:   uint32(r),
	}, nil
}

func (srv *Server) AddOnions(stream pb.Mixnet_AddOnionsServer) error {
	md, err := parseMetadata(stream.Context())
	if err != nil {
		return err
	}
	round := md.round

	st, err := srv.getRound(md.service, round)
	if err != nil {
		return err
	}
	if err := srv.authPrev(stream.Context(), st); err != nil {
		return err
	}

	st.mu.Lock()
	numIncoming := st.numIncoming
	if numIncoming == 0 {
		st.mu.Unlock()
		return errors.New("did not set numIncoming")
	}
	st.mu.Unlock()

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if req.Offset+uint32(len(req.Onions)) > numIncoming {
			return errors.New("overflowing onions (offset=%d, onions=%d, incoming=%d)", req.Offset, len(req.Onions), st.numIncoming)
		}

		st.mu.Lock()
		if st.acceptingOnions {
			st.decryptWg.Add(1)
			srv.decryptionJobs <- decryptionJob{
				st:    st,
				round: round,
				req:   req,
			}
		}
		st.mu.Unlock()
	}

	return nil
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
	if st.closed {
		st.mu.Unlock()
		return &pb.Nothing{}, st.err
	}
	// Don't allow new decryption jobs.
	st.acceptingOnions = false
	st.mu.Unlock()

	// Wait for outstanding decryption jobs to finish.
	st.decryptWg.Wait()

	st.mu.Lock()
	defer st.mu.Unlock()

	st.closed = true

	logger := log.WithFields(log.Fields{
		"srv":    st.myPos,
		"rpc":    "CloseRound",
		"round":  req.Round,
		"onions": len(st.incoming),
	})
	logger.Info("Closing round")

	srv.filterIncoming(st)

	var replies [][]byte
	// if not last server
	if st.myPos < len(st.chain)-1 {
		<-st.noiseDone
		numNonNoise := len(st.incoming)
		outgoing := append(st.incoming, st.noise...)
		st.noise = nil
		st.incoming = nil

		shuffler := shuffle.New(rand.Reader, len(outgoing))
		shuffler.Shuffle(outgoing)

		replies, err = srv.mixClient.RunRound(ctx, st.chain[st.myPos+1], req.Service, req.Round, outgoing)
		if err != nil {
			return nil, errors.New("RunRound %d->%d: %s", st.myPos, st.myPos+1, err)
		}

		shuffler.Unshuffle(replies)
		// drop the noise
		replies = replies[:numNonNoise]
	} else {
		start := time.Now()
		replies = srv.Services[req.Service].SortReplies(st.incoming)
		duration := time.Now().Sub(start)
		logger.WithFields(log.Fields{"duration": duration}).Infof("Sorted replies")

		st.incoming = nil
	}

	// Encrypt the replies.
	st.replies = make([][]byte, len(st.incomingIndex))
	go func() {
		replyMsgSize := (len(st.chain)-st.myPos-1)*box.Overhead + srv.Services[req.Service].SizeReplyMessage()
		concurrency.ParallelFor(len(st.replies), func(p *concurrency.P) {
			freshKey := new([32]byte)
			nonce := BackwardNonce(req.Round)
			var key *[32]byte
			emptyMsg := make([]byte, replyMsgSize)
			for i, ok := p.Next(); ok; i, ok = p.Next() {
				var msg []byte
				v := st.incomingIndex[i]
				if v > -1 {
					msg = replies[v]
					key = &st.sharedKeys[i]
				}
				if len(msg) != replyMsgSize {
					msg = emptyMsg
					rand.Read(freshKey[:])
					key = freshKey
				}

				st.replies[i] = box.SealAfterPrecomputation(nil, msg, nonce, key)
			}
		})
		close(st.encryptDone)
	}()

	return &pb.Nothing{}, nil
}

func (srv *Server) GetOnions(req *pb.GetOnionsRequest, stream pb.Mixnet_GetOnionsServer) error {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return err
	}
	if err := srv.authPrev(stream.Context(), st); err != nil {
		return err
	}

	// Wait for replies to finish encrypting.
	<-st.encryptDone

	if req.Offset+req.Count > uint32(len(st.replies)) {
		return errors.New("invalid offset and count (offset=%d count=%d replies=%d)", req.Offset, req.Count, len(st.replies))
	}
	replies := st.replies[req.Offset : req.Offset+req.Count]

	spans := concurrency.Spans(len(replies), 16)
	for _, span := range spans {
		err := stream.Send(&pb.GetOnionsResponse{
			Offset: req.Offset + uint32(span.Start),
			Onions: replies[span.Start : span.Start+span.Count],
		})
		if err != nil {
			return err
		}
	}

	return nil
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
	conns map[[ed25519.PublicKeySize]byte][]*grpc.ClientConn
}

func (c *Client) getConn(server PublicServerConfig) (pb.MixnetClient, error) {
	conns, err := c.getConns(1, server)
	if err != nil {
		return nil, err
	}
	return conns[0], nil
}

func (c *Client) getConns(count int, server PublicServerConfig) ([]pb.MixnetClient, error) {
	var k [ed25519.PublicKeySize]byte
	copy(k[:], server.Key)

	c.mu.Lock()
	if c.conns == nil {
		c.conns = make(map[[ed25519.PublicKeySize]byte][]*grpc.ClientConn)
	}
	ccs := c.conns[k]
	c.mu.Unlock()

	if len(ccs) < count {
		creds := credentials.NewTLS(edtls.NewTLSClientConfig(c.Key, server.Key))

		opts := []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithWriteBufferSize(128 * 1024),
			grpc.WithReadBufferSize(128 * 1024),
			grpc.WithInitialWindowSize(2 << 18),
			grpc.WithInitialConnWindowSize(2 << 18),
		}

		newConns := count - len(ccs)
		for i := 0; i < newConns; i++ {
			cc, err := grpc.Dial(server.Address, opts...)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			ccs = append(ccs, cc)
			c.conns[k] = ccs
			c.mu.Unlock()
		}
	}

	clients := make([]pb.MixnetClient, count)
	for i := range clients {
		clients[i] = pb.NewMixnetClient(ccs[i])
	}

	return clients, nil
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

	errs := make(chan error, 1)
	for i, server := range servers {
		go func(i int, server PublicServerConfig) {
			response, err := conns[i].NewRound(ctx, newRoundReq)
			if err != nil {
				errs <- errors.Wrap(err, "server %s: NewRound", server.Address)
				return
			}
			key := new([32]byte)
			copy(key[:], response.OnionKey[:])
			settings.OnionKeys[i] = key
			errs <- nil
		}(i, server)
	}
	var newRoundErr error
	for i := 0; i < len(servers); i++ {
		err := <-errs
		if err != nil && newRoundErr == nil {
			newRoundErr = err
		}
	}
	if newRoundErr != nil {
		return nil, newRoundErr
	}

	setSettingsReq := &pb.SetRoundSettingsRequest{
		Settings: settings.Proto(),
	}
	signatures := make([][]byte, len(servers))
	for i, server := range servers {
		go func(i int, server PublicServerConfig) {
			response, err := conns[i].SetRoundSettings(ctx, setSettingsReq)
			if err != nil {
				errs <- errors.Wrap(err, "server %s: SetRoundSettings", server.Address)
				return
			}
			signatures[i] = response.Signature
			errs <- nil
		}(i, server)
	}
	var setSettingsErr error
	for i := 0; i < len(servers); i++ {
		err := <-errs
		if err != nil && setSettingsErr == nil {
			setSettingsErr = err
		}
	}
	if setSettingsErr != nil {
		return nil, setSettingsErr
	}
	return signatures, nil
}

func streamAddOnions(ctx context.Context, conn pb.MixnetClient, offset int, onions [][]byte) error {
	spans := concurrency.Spans(len(onions), 16)
	stream, err := conn.AddOnions(ctx)
	if err != nil {
		return err
	}

	for _, span := range spans {
		err := stream.Send(&pb.AddOnionsRequest{
			Offset: uint32(offset + span.Start),
			Onions: onions[span.Start : span.Start+span.Count],
		})
		if err != nil {
			return err
		}
	}
	_, err = stream.CloseAndRecv()
	if err == io.EOF {
		return nil
	}
	return err
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

	md := metadata.Pairs(
		"service", service,
		"round", fmt.Sprintf("%d", round),
	)
	addCtx := metadata.NewOutgoingContext(ctx, md)

	numSpans := len(onions) / 5
	if numSpans == 0 {
		numSpans = 1
	}
	spans := concurrency.Spans(len(onions), numSpans)
	conns, err := c.getConns(len(spans), server)
	if err != nil {
		return nil, err
	}
	errs := make(chan error, 1)
	start := time.Now()
	for i, span := range spans {
		conn := conns[i]
		go func(span concurrency.Span) {
			errs <- streamAddOnions(addCtx, conn, span.Start, onions[span.Start:span.Start+span.Count])
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
		return nil, errors.Wrap(addErr, "adding onions")
	}
	duration := time.Now().Sub(start)
	sizeOnion := 0
	if len(onions) > 0 {
		sizeOnion = len(onions[0])
	}
	log.WithFields(log.Fields{"round": round, "duration": duration, "onions": len(onions), "sizeOnion": sizeOnion}).Infof("RunRound: added onions to next mixer")

	start = time.Now()
	closeReq := &pb.CloseRoundRequest{
		Service: service,
		Round:   round,
	}
	_, closeErr := conn.CloseRound(ctx, closeReq)
	if closeErr != nil {
		return nil, closeErr
	}
	duration = time.Now().Sub(start)
	log.WithFields(log.Fields{"round": round, "duration": duration, "onions": len(onions)}).Infof("RunRound: closed round")

	start = time.Now()
	replies := make([][]byte, len(onions))
	spans = concurrency.Spans(len(replies), numSpans)
	conns, err = c.getConns(len(spans), server)
	if err != nil {
		return nil, err
	}
	getOnions := func(span concurrency.Span, conn pb.MixnetClient) error {
		stream, err := conn.GetOnions(ctx, &pb.GetOnionsRequest{
			Service: service,
			Round:   round,
			Offset:  uint32(span.Start),
			Count:   uint32(span.Count),
		})
		if err != nil {
			return err
		}
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			copy(replies[resp.Offset:], resp.Onions)
		}
		return nil
	}
	for i, span := range spans {
		conn := conns[i]
		go func(span concurrency.Span) {
			errs <- getOnions(span, conn)
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
		return nil, errors.Wrap(getErr, "fetching onions")
	}
	duration = time.Now().Sub(start)
	log.WithFields(log.Fields{"round": round, "duration": duration, "onions": len(onions)}).Infof("RunRound: fetched onions from mixer")

	// Delete the round asynchronously.
	go func() {
		_, err := conn.DeleteRound(context.Background(), &pb.DeleteRoundRequest{
			Service: service,
			Round:   round,
		})
		if err != nil {
			log.WithFields(log.Fields{"round": round}).Errorf("RunRound: failed to delete round: %s", err)
		}
	}()

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
