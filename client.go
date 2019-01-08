// Copyright 2015 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package vuvuzela

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/coordinator"
	"vuvuzela.io/vuvuzela/mixnet"
)

type Client struct {
	PersistPath        string
	CoordinatorLatency time.Duration // Eventually we will measure this.

	ConfigClient *config.Client
	Handler      ConvoHandler

	mu          sync.Mutex
	rounds      map[uint32]*roundState
	conn        typesocket.Conn
	latestRound uint32

	convoConfig     *config.SignedConfig
	convoConfigHash string
}

type roundState struct {
	Config       *convo.ConvoConfig
	ConfigParent *config.SignedConfig

	mu        sync.Mutex
	OnionKeys [][]*[32]byte // [msg][mixer]
}

type ConvoHandler interface {
	Outgoing(round uint32) []*convo.DeadDropMessage
	Replies(round uint32, messages [][]byte)
	NewConfig(chain []*config.SignedConfig)
	Error(err error)
	DebugError(err error)
	GlobalAnnouncement(message string)
}

func (c *Client) ConnectConvo() (chan error, error) {
	if c.Handler == nil {
		return nil, errors.New("no convo handler")
	}

	c.mu.Lock()
	if c.rounds == nil {
		c.rounds = make(map[uint32]*roundState)
	}
	c.mu.Unlock()

	// Fetch the current config to get the coordinator's key and address.
	convoConfig, err := c.ConfigClient.CurrentConfig("Convo")
	if err != nil {
		return nil, errors.Wrap(err, "fetching latest convo config")
	}
	convoInner := convoConfig.Inner.(*convo.ConvoConfig)

	wsAddr := fmt.Sprintf("wss://%s/convo/ws", convoInner.Coordinator.Address)
	conn, err := typesocket.Dial(wsAddr, convoInner.Coordinator.Key)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	disconnect := make(chan error, 1)
	go func() {
		disconnect <- conn.Serve(c.convoMux())
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	return disconnect, nil
}

func (c *Client) CloseConvo() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		conn := c.conn
		c.conn = nil
		return conn.Close()
	}
	return nil
}

func (c *Client) LatestRound() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return 0, errors.New("not connected to convo service")
	}
	return c.latestRound, nil
}

func (c *Client) setLatestRound(round uint32) {
	c.mu.Lock()
	if round > c.latestRound {
		c.latestRound = round
	}
	c.mu.Unlock()
}

func (c *Client) convoMux() typesocket.Mux {
	return typesocket.NewMux(map[string]interface{}{
		"announcement": c.globalAnnouncement,
		"newround":     c.newConvoRound,
		"reply":        c.openReplyOnion,
		"error":        c.convoRoundError,
	})
}

func (c *Client) globalAnnouncement(conn typesocket.Conn, v coordinator.GlobalAnnouncement) {
	c.Handler.GlobalAnnouncement(v.Message)
}

func (c *Client) convoRoundError(conn typesocket.Conn, v coordinator.RoundError) {
	if strings.Contains(v.Err, "round is closed:") || strings.Contains(v.Err, "round not found") {
		// The client now supports retransmission so it's safe to ignore these errors by default.
		c.Handler.DebugError(errors.New("error from convo coordinator: round %d: %s", v.Round, v.Err))
	} else {
		c.Handler.Error(errors.New("error from convo coordinator: round %d: %s", v.Round, v.Err))
	}
}

func (c *Client) newConvoRound(conn typesocket.Conn, v coordinator.NewRound) {
	c.setLatestRound(v.Round)

	if time.Until(v.EndTime) < 20*time.Millisecond {
		c.Handler.DebugError(errors.New("newConvoRound %d: skipping round (only %s left)", v.Round, time.Until(v.EndTime)))
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.rounds[v.Round]
	if ok {
		if st.ConfigParent.Hash() != v.ConfigHash {
			c.Handler.Error(errors.New("coordinator announced different configs round %d", v.Round))
		}
		return
	}

	var conf *config.SignedConfig
	if v.ConfigHash == c.convoConfigHash {
		// common case
		conf = c.convoConfig
	} else {
		// Fetch the new config.
		configs, err := c.ConfigClient.FetchAndVerifyChain(c.convoConfig, v.ConfigHash)
		if err != nil {
			c.Handler.Error(errors.Wrap(err, "fetching convo config"))
			return
		}

		c.Handler.NewConfig(configs)

		newConfig := configs[0]
		c.convoConfig = newConfig
		c.convoConfigHash = v.ConfigHash

		if err := c.persistLocked(); err != nil {
			panic("failed to persist state: " + err.Error())
		}

		conf = newConfig
	}

	st = &roundState{
		Config:       conf.Inner.(*convo.ConvoConfig),
		ConfigParent: conf,
	}
	c.rounds[v.Round] = st
	// Run the rest of the round in a new goroutine to release the client lock.
	go c.runRound(conn, st, v)
	return
}

func (c *Client) runRound(conn typesocket.Conn, st *roundState, v coordinator.NewRound) {
	round := v.Round
	settingsMsg := v.MixSettings.SigningMessage()

	for i, mixer := range st.Config.MixServers {
		if !ed25519.Verify(mixer.Key, settingsMsg, v.MixSignatures[i]) {
			err := errors.New(
				"round %d: failed to verify mixnet settings for key %s",
				round, base32.EncodeToString(mixer.Key),
			)
			c.Handler.Error(err)
			return
		}
	}

	if time.Until(v.EndTime) < c.CoordinatorLatency {
		c.Handler.DebugError(errors.New("runRound %d: skipping round (only %s left)", v.Round, time.Until(v.EndTime)))
		return
	}

	time.Sleep(time.Until(v.EndTime) - c.CoordinatorLatency - 10*time.Millisecond)

	outgoing := c.Handler.Outgoing(round)
	onionKeys := make([][]*[32]byte, len(outgoing))
	onions := make([][]byte, len(outgoing))
	for i, deadDropMsg := range outgoing {
		msg := deadDropMsg.Marshal()
		onions[i], onionKeys[i] = onionbox.Seal(msg, mixnet.ForwardNonce(round), v.MixSettings.OnionKeys)
	}

	st.mu.Lock()
	st.OnionKeys = onionKeys
	st.mu.Unlock()

	if time.Until(v.EndTime) < 10*time.Millisecond {
		c.Handler.DebugError(errors.New("runRound %d: abandoning round (only %s left)", round, time.Until(v.EndTime)))
		return
	}
	conn.Send("onion", coordinator.OnionMsg{
		Round:  round,
		Onions: onions,
	})
}

func (c *Client) openReplyOnion(conn typesocket.Conn, v coordinator.OnionMsg) {
	c.mu.Lock()
	st, ok := c.rounds[v.Round]
	c.mu.Unlock()
	if !ok {
		c.Handler.Error(errors.New("openReplyOnion: round %d not configured", v.Round))
		return
	}

	st.mu.Lock()
	onionKeys := st.OnionKeys
	st.mu.Unlock()

	if onionKeys == nil {
		c.Handler.Error(errors.New("openReplyOnion: didn't generate onion keys for round %d", v.Round))
		return
	}

	if len(st.OnionKeys) != len(v.Onions) {
		err := errors.New("round %d: expected %d onions, got %d", v.Round, len(st.OnionKeys), len(v.Onions))
		c.Handler.Error(err)
		return
	}

	expectedOnionSize := convo.SizeEncryptedMessageBody + len(st.Config.MixServers)*box.Overhead
	msgs := make([][]byte, len(v.Onions))
	for i, onion := range v.Onions {
		if len(onion) != expectedOnionSize {
			err := errors.New("convo round %d: received malformed onion: got %d bytes, want %d bytes", v.Round, len(onion), expectedOnionSize)
			c.Handler.Error(err)
			continue
		}
		msg, ok := onionbox.Open(onion, mixnet.BackwardNonce(v.Round), st.OnionKeys[i])
		if !ok {
			err := errors.New("convo round %d: failed to decrypt onion", v.Round)
			c.Handler.Error(err)
		}
		msgs[i] = msg
	}

	c.Handler.Replies(v.Round, msgs)

	c.mu.Lock()
	delete(c.rounds, v.Round)
	c.mu.Unlock()
}
