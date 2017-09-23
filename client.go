// Copyright 2015 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package vuvuzela

import (
	"fmt"
	"sync"

	"github.com/davidlazar/go-crypto/encoding/base32"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/coordinator"
	"vuvuzela.io/vuvuzela/mixnet"
)

type Client struct {
	CoordinatorAddress string
	CoordinatorKey     ed25519.PublicKey
	PersistPath        string

	conn typesocket.Conn

	mu           sync.Mutex
	rounds       map[uint32]*roundState
	convoHandler ConvoHandler

	convoConfig     *config.SignedConfig
	convoConfigHash string
}

type roundState struct {
	OnionKeys    []*[32]byte
	Handler      ConvoHandler
	Config       *convo.ConvoConfig
	ConfigParent *config.SignedConfig
}

type ConvoHandler interface {
	NextMessage(round uint32) *convo.DeadDropMessage
	Reply(round uint32, msg []byte)
}

func (c *Client) SetConvoHandler(convo ConvoHandler) {
	c.mu.Lock()
	c.convoHandler = convo
	c.mu.Unlock()
}

func (c *Client) Connect() error {
	// TODO check if already connected
	if c.convoHandler == nil {
		return fmt.Errorf("no convo handler")
	}

	if c.rounds == nil {
		c.rounds = make(map[uint32]*roundState)
	}

	wsAddr := fmt.Sprintf("wss://%s/convo/ws", c.CoordinatorAddress)
	conn, err := typesocket.Dial(wsAddr, c.CoordinatorKey, c.convoMux())
	if err != nil {
		return err
	}
	c.conn = conn

	return nil
}

func (c *Client) convoMux() typesocket.Mux {
	return typesocket.NewMux(map[string]interface{}{
		"newround": c.newConvoRound,
		"mix":      c.sendConvoOnion,
		"reply":    c.openReplyOnion,
		"error":    c.convoRoundError,
	})
}

func (c *Client) convoRoundError(conn typesocket.Conn, v coordinator.RoundError) {
	log.WithFields(log.Fields{"round": v.Round}).Errorf("round error: %s", v.Err)
}

func (c *Client) newConvoRound(conn typesocket.Conn, v coordinator.NewRound) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.rounds[v.Round]
	if ok {
		if st.ConfigParent.Hash() != v.ConfigHash {
			log.Errorf("%s", errors.New("coordinator announced different configs round %d", v.Round))
		}
		return
	}

	// common case
	if v.ConfigHash == c.convoConfigHash {
		c.rounds[v.Round] = &roundState{
			Config:       c.convoConfig.Inner.(*convo.ConvoConfig),
			ConfigParent: c.convoConfig,
		}
		return
	}

	configs, err := config.Client{
		ConfigURL:  fmt.Sprintf("https://%s/convo/config", c.CoordinatorAddress),
		ServerKey:  c.CoordinatorKey,
		HTTPClient: &edhttp.Client{},
	}.FetchAndVerifyConfig(c.convoConfig, v.ConfigHash)
	if err != nil {
		log.Errorf("%s", errors.Wrap(err, "fetching convo config"))
		return
	}

	newConfig := configs[0]
	c.convoConfig = newConfig
	c.convoConfigHash = v.ConfigHash

	if err := c.Persist(); err != nil {
		panic("failed to persist state: " + err.Error())
	}

	c.rounds[v.Round] = &roundState{
		Config:       newConfig.Inner.(*convo.ConvoConfig),
		ConfigParent: newConfig,
	}
}

func (c *Client) sendConvoOnion(conn typesocket.Conn, v coordinator.MixRound) {
	round := v.MixSettings.Round

	c.mu.Lock()
	st, ok := c.rounds[round]
	c.mu.Unlock()
	if !ok {
		err := errors.New("sendConvoOnion: round %d not configured", round)
		log.Errorf("%s", err)
		return
	}

	settingsMsg := v.MixSettings.SigningMessage()

	for i, mixer := range st.Config.MixServers {
		if !ed25519.Verify(mixer.Key, settingsMsg, v.MixSignatures[i]) {
			err := errors.New(
				"round %d: failed to verify mixnet settings for key %s",
				round, base32.EncodeToString(mixer.Key),
			)
			log.Errorf("%s", err)
			return
		}
	}

	c.mu.Lock()
	roundHandler := c.convoHandler
	c.mu.Unlock()

	msg := roundHandler.NextMessage(round).Marshal()
	ctxt, keys := onionbox.Seal(msg, mixnet.ForwardNonce(round), v.MixSettings.OnionKeys)

	c.mu.Lock()
	st.Handler = roundHandler
	st.OnionKeys = keys
	c.mu.Unlock()

	conn.Send("onion", coordinator.OnionMsg{
		Round: round,
		Onion: ctxt,
	})
}

func (c *Client) openReplyOnion(conn typesocket.Conn, v coordinator.OnionMsg) {
	c.mu.Lock()
	st, ok := c.rounds[v.Round]
	c.mu.Unlock()
	if !ok {
		log.WithFields(log.Fields{"round": v.Round}).Error("round not found")
		return
	}

	msg, ok := onionbox.Open(v.Onion, mixnet.BackwardNonce(v.Round), st.OnionKeys)
	if !ok {
		log.WithFields(log.Fields{"round": v.Round}).Error("failed to decrypt onion")
	}

	st.Handler.Reply(v.Round, msg)

	c.mu.Lock()
	delete(c.rounds, v.Round)
	c.mu.Unlock()
}
