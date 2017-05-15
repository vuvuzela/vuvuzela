// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package coordinator implements the entry/coordinator server.
package coordinator

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/internal/ioutil2"
	"vuvuzela.io/vuvuzela/mixnet"
)

// Server is the coordinator (entry) server for the
// Vuvuzela conversation protocol.
type Server struct {
	MixServers   []*vrpc.Client
	MixWait      time.Duration
	NumMailboxes uint32

	RoundWait time.Duration

	PersistPath string

	mu             sync.Mutex
	round          uint32
	onions         []onion
	closed         bool
	shutdown       chan struct{}
	latestMixRound *MixRound

	hub *typesocket.Hub
}

type onion struct {
	sender typesocket.Conn
	data   []byte
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

	round, err := loadPersistedState(srv.PersistPath)
	if err != nil {
		return err
	}
	srv.round = round + 1
	srv.onions = make([]onion, 0, 128)
	srv.closed = false
	srv.shutdown = make(chan struct{})

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

// version is the current version number of the persisted state format.
const version byte = 0

func loadPersistedState(path string) (round uint32, err error) {
	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, persistState(path, 0)
	} else if err != nil {
		return 0, err
	}

	if len(data) < 5 {
		return 0, fmt.Errorf("short data: want %d bytes, got %d", 5, len(data))
	}

	ver := data[0]
	if ver != version {
		return 0, fmt.Errorf("unexpected version: want version %d, got %d", version, ver)
	}

	round = binary.BigEndian.Uint32(data[1:])
	return round, nil
}

func persistState(path string, round uint32) error {
	var data [5]byte
	data[0] = version
	binary.BigEndian.PutUint32(data[1:], round)
	return ioutil2.WriteFileAtomic(path, data[:], 0600)
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.hub.ServeHTTP(w, r)
}

type OnionMsg struct {
	Round uint32
	Onion []byte
}

type MixRound struct {
	MixSettings   mixnet.RoundSettings
	MixSignatures [][]byte
	EndTime       time.Time
}

type RoundError struct {
	Round uint32
	Err   string
}

func (srv *Server) onConnect(c typesocket.Conn) error {
	srv.mu.Lock()
	mixRound := srv.latestMixRound
	srv.mu.Unlock()

	if mixRound != nil {
		err := c.Send("mix", mixRound)
		if err != nil {
			return err
		}
	}

	return nil
}

func (srv *Server) incomingOnion(c typesocket.Conn, o OnionMsg) {
	srv.mu.Lock()
	round := srv.round
	if o.Round == round {
		srv.onions = append(srv.onions, onion{
			sender: c,
			data:   o.Onion,
		})
	}
	srv.mu.Unlock()
	if o.Round != round {
		log.Errorf("got onion for wrong round (want %d, got %d)", round, o.Round)
		c.Send("error", RoundError{
			Round: o.Round,
			Err:   fmt.Sprintf("wrong round (want %d)", round),
		})
	}
}

func (srv *Server) loop() {
	round := srv.round

	for {
		logger := log.WithFields(log.Fields{"round": round})

		if err := persistState(srv.PersistPath, round); err != nil {
			logger.Errorf("error persisting state: %s", err)
			break
		}

		logger.Info("starting new round")

		// TODO perhaps pkg.NewRound, mixnet.NewRound, hub.Broadcast, etc
		// should take a Context for better cancelation.

		mixSettings := mixnet.RoundSettings{
			Round: round,
		}
		mixSigs, err := mixnet.NewRound(srv.MixServers, &mixSettings)
		if err != nil {
			logger.WithFields(log.Fields{"call": "mixnet.NewRound"}).Error(err)
			if !srv.sleep(10 * time.Second) {
				break
			}
			continue
		}

		roundEnd := time.Now().Add(srv.MixWait)
		mixRound := &MixRound{
			MixSettings:   mixSettings,
			MixSignatures: mixSigs,
			EndTime:       roundEnd,
		}
		srv.mu.Lock()
		srv.latestMixRound = mixRound
		srv.mu.Unlock()

		logger.Info("announcing mixnet settings")
		srv.hub.Broadcast("mix", mixRound)

		if !srv.sleep(srv.MixWait) {
			break
		}

		logger.Info("running round")
		srv.mu.Lock()
		go srv.runRound(round, srv.onions)

		round++
		srv.round = round
		srv.onions = make([]onion, 0, len(srv.onions))
		srv.mu.Unlock()

		logger.Info("waiting for next round")
		if !srv.sleep(srv.RoundWait) {
			break
		}
	}

	log.WithFields(log.Fields{"round": round}).Info("shutting down")
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

func (srv *Server) runRound(round uint32, out []onion) {
	onions := make([][]byte, len(out))
	senders := make([]typesocket.Conn, len(out))
	for i, o := range out {
		onions[i] = o.data
		senders[i] = o.sender
	}

	logger := log.WithFields(log.Fields{"round": round})
	logger.WithFields(log.Fields{"onions": len(onions)}).Info("start RunRound")
	start := time.Now()

	replies, err := mixnet.RunRound(srv.MixServers[0], round, onions)
	if err != nil {
		logger.WithFields(log.Fields{"call": "RunRound"}).Error(err)
		srv.hub.Broadcast("error", RoundError{Round: round, Err: "server error"})
		return
	}
	end := time.Now()
	logger.WithFields(log.Fields{"duration": end.Sub(start)}).Info("end RunRound")

	concurrency.ParallelFor(len(replies), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			senders[i].Send("reply", OnionMsg{
				Round: round,
				Onion: replies[i],
			})
		}
	})
}
