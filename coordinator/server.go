// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package coordinator implements the entry/coordinator server.
package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/context"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/mixnet"
)

// Server is the coordinator (entry) server for the
// Vuvuzela conversation protocol.
type Server struct {
	Service    string
	PrivateKey ed25519.PrivateKey

	ConfigClient *config.Client

	RoundDelay time.Duration

	PersistPath string

	// round is updated atomically.
	round uint32

	mu           sync.Mutex
	rounds       map[uint32]*roundState
	closed       bool
	shutdown     chan struct{}
	freshConfig  bool
	latestConfig *config.SignedConfig

	hub          *typesocket.Hub
	mixnetClient *mixnet.Client
}

type roundState struct {
	roundInfo *NewRound

	mu     sync.Mutex
	open   bool
	onions []onionBundle
}

type onionBundle struct {
	sender typesocket.Conn
	onions [][]byte
}

var ErrServerClosed = errors.New("coordinator: server closed")

func (srv *Server) Run() error {
	if srv.PersistPath == "" {
		return errors.New("no persist path specified")
	}

	mux := typesocket.NewMux(map[string]interface{}{
		"onion": srv.incomingOnion,
	})
	srv.hub = &typesocket.Hub{
		Mux: mux,
	}

	srv.mixnetClient = &mixnet.Client{
		Key: srv.PrivateKey,
	}

	srv.mu.Lock()
	srv.rounds = make(map[uint32]*roundState)
	srv.closed = false
	srv.shutdown = make(chan struct{})
	srv.mu.Unlock()

	go srv.updateConfigLoop()
	// Give the config loop a chance before firing up the main loop.
	time.Sleep(2 * time.Second)

	go srv.loop()

	return nil
}

func (srv *Server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// This could be better if we had Contexts everywhere,
	// but only tests should need to close the server.
	if !srv.closed {
		close(srv.shutdown)
		srv.closed = true
		return nil
	} else {
		return ErrServerClosed
	}
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/ws"):
		srv.hub.ServeHTTP(w, r)
	case strings.HasPrefix(r.URL.Path, "/sendannouncement"):
		srv.sendAnnouncementHandler(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

type OnionMsg struct {
	Round  uint32
	Onions [][]byte
}

type NewRound struct {
	Round         uint32
	ConfigHash    string
	MixSettings   mixnet.RoundSettings
	MixSignatures [][]byte
	EndTime       time.Time
}

type RoundError struct {
	Round uint32
	Err   string
}

type GlobalAnnouncement struct {
	Message string
}

func (srv *Server) sendAnnouncementHandler(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		http.Error(w, "no peer certificate", http.StatusBadRequest)
		return
	}
	key := edtls.GetSigningKey(req.TLS.PeerCertificates[0])
	if len(key) != ed25519.PublicKeySize {
		http.Error(w, "invalid peer key", http.StatusBadRequest)
		return
	}

	srv.mu.Lock()
	conf := srv.latestConfig
	srv.mu.Unlock()
	if conf == nil {
		http.Error(w, "no convo config", http.StatusBadRequest)
		return
	}

	gx := -1
	for i, g := range conf.Guardians {
		if bytes.Equal(g.Key, key) {
			gx = i
			break
		}
	}
	if gx == -1 {
		http.Error(w, "not a guardian", http.StatusBadRequest)
		return
	}

	body := http.MaxBytesReader(w, req.Body, 4096)
	args := GlobalAnnouncement{}
	err := json.NewDecoder(body).Decode(&args)
	if err != nil {
		http.Error(w, "error decoding json", http.StatusBadRequest)
		return
	}

	err = srv.hub.Broadcast("announcement", args)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to broadcast message: %s", err), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK"))
}

func (srv *Server) onConnect(c typesocket.Conn) error {
	rounds := make([]*roundState, 0, 4)
	srv.mu.Lock()
	for _, st := range srv.rounds {
		rounds = append(rounds, st)
	}
	srv.mu.Unlock()

	for _, st := range rounds {
		if time.Until(st.roundInfo.EndTime) < 100*time.Millisecond {
			continue
		}
		err := c.Send("newround", st.roundInfo)
		if err != nil {
			return err
		}
	}

	return nil
}

func (srv *Server) incomingOnion(c typesocket.Conn, o OnionMsg) {
	srv.mu.Lock()
	st, ok := srv.rounds[o.Round]
	srv.mu.Unlock()
	if !ok {
		c.Send("error", RoundError{
			Round: o.Round,
			Err:   "round not found",
		})
		return
	}

	ok = false
	st.mu.Lock()
	if st.open {
		st.onions = append(st.onions, onionBundle{
			sender: c,
			onions: o.Onions,
		})
		ok = true
	}
	st.mu.Unlock()

	if !ok {
		c.Send("error", RoundError{
			Round: o.Round,
			Err:   fmt.Sprintf("round is closed: deadline was %s ago", time.Now().Sub(st.roundInfo.EndTime)),
		})
	}
}

func (srv *Server) updateConfigLoop() {
	for {
		log.Infof("Fetching latest config")

		currentConfig, err := srv.ConfigClient.CurrentConfig(srv.Service)
		if err != nil {
			log.Errorf("failed to fetch current config: %s", err)
			srv.mu.Lock()
			srv.freshConfig = false
			srv.mu.Unlock()
			time.Sleep(10 * time.Second)
			continue
		}

		srv.mu.Lock()
		srv.freshConfig = true
		srv.latestConfig = currentConfig
		srv.mu.Unlock()

		time.Sleep(1 * time.Minute)
	}
}

func (srv *Server) loop() {
	numInFlight := 5
	flights := make(chan struct{}, numInFlight)
	for i := 0; i < numInFlight; i++ {
		flights <- struct{}{}
	}

	atomic.AddUint32(&srv.round, 100)

	lastDeadline := time.Now()
	for _ = range flights {
		round := atomic.AddUint32(&srv.round, 1)

		// Persist every 20 rounds.
		if round%uint32(20) == 0 {
			go func() {
				err := srv.Persist()
				if err != nil {
					panic(err)
				}
			}()
		}

		if time.Now().After(lastDeadline) {
			lastDeadline = time.Now()
		}
		lastDeadline = lastDeadline.Add(srv.RoundDelay)
		go func() {
			srv.runRound(context.Background(), round, lastDeadline)
			flights <- struct{}{}
		}()
	}

	log.Info("Shutting down")
}

func (srv *Server) runRound(ctx context.Context, round uint32, deadline time.Time) {
	defer func() {
		srv.mu.Lock()
		delete(srv.rounds, round)
		srv.mu.Unlock()
	}()

	logger := log.WithFields(log.Fields{"round": round})

	srv.mu.Lock()
	conf := srv.latestConfig
	isFresh := srv.freshConfig
	srv.mu.Unlock()

	if !isFresh {
		logger.Errorf("stale config")
		time.Sleep(10 * time.Second)
		return
	}

	mixServers := conf.Inner.(*convo.ConvoConfig).MixServers
	logger.Infof("Starting new round with %d mixers", len(mixServers))

	mixSettings := mixnet.RoundSettings{
		Service: "Convo",
		Round:   round,
	}
	mixSigs, err := srv.mixnetClient.NewRound(context.Background(), mixServers, &mixSettings)
	if err != nil {
		logger.WithFields(log.Fields{"call": "mixnet.NewRound"}).Error(err)
		return
	}

	roundInfo := &NewRound{
		Round:         round,
		ConfigHash:    conf.Hash(),
		MixSettings:   mixSettings,
		MixSignatures: mixSigs,
		EndTime:       deadline,
	}
	st := &roundState{
		roundInfo: roundInfo,
		open:      true,
		onions:    make([]onionBundle, 0, 512),
	}
	srv.mu.Lock()
	srv.rounds[round] = st
	srv.mu.Unlock()

	logger.Info("Announcing mixnet settings")
	srv.hub.Broadcast("newround", roundInfo)

	if !srv.sleep(time.Until(deadline)) {
		return
	}

	st.mu.Lock()
	st.open = false
	onions := st.onions
	st.mu.Unlock()

	srv.mixOnions(ctx, mixServers[0], round, onions)
}

func (srv *Server) sleep(d time.Duration) bool {
	timer := time.NewTimer(d)
	select {
	case <-srv.shutdown:
		timer.Stop()
		return false
	case <-timer.C:
		return true
	}
}

type senderRange struct {
	sender     typesocket.Conn
	start, end int
}

func (srv *Server) mixOnions(ctx context.Context, firstServer mixnet.PublicServerConfig, round uint32, out []onionBundle) {
	numOnions := 0
	for _, bundle := range out {
		numOnions += len(bundle.onions)
	}

	onions := make([][]byte, 0, numOnions)
	senders := make([]senderRange, len(out))
	for i, o := range out {
		senders[i] = senderRange{
			sender: o.sender,
			start:  len(onions),
			end:    len(onions) + len(o.onions),
		}
		onions = append(onions, o.onions...)
	}

	logger := log.WithFields(log.Fields{"round": round, "onions": len(onions)})
	logger.Info("Start mixing")
	start := time.Now()

	replies, err := srv.mixnetClient.RunRoundBidirectional(ctx, firstServer, srv.Service, round, onions)
	if err != nil {
		logger.WithFields(log.Fields{"call": "RunRound"}).Error(err)
		srv.hub.Broadcast("error", RoundError{Round: round, Err: "server error"})
		return
	}

	end := time.Now()
	logger.WithFields(log.Fields{"duration": end.Sub(start)}).Info("Done mixing")

	concurrency.ParallelFor(len(senders), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			sr := senders[i]
			sr.sender.Send("reply", OnionMsg{
				Round:  round,
				Onions: replies[sr.start:sr.end],
			})
		}
	})
}
