package main

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/vuvuzela/coordinator"
	"vuvuzela.io/vuvuzela/mixnet"
)

type Client struct {
	Mixers      []ed25519.PublicKey
	EntryServer string

	conn typesocket.Conn

	mu           sync.Mutex
	rounds       map[uint32]*roundState
	convoHandler ConvoHandler
}

type roundState struct {
	OnionKeys []*[32]byte
	Handler   ConvoHandler
}

type ConvoHandler interface {
	NextMessage(round uint32) *mixnet.MixMessage
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

	wsAddr := fmt.Sprintf("ws://%s/ws", c.EntryServer)
	conn, err := typesocket.Dial(wsAddr, c.convoMux())
	if err != nil {
		return err
	}
	c.conn = conn

	return nil
}

func (c *Client) convoMux() typesocket.Mux {
	return typesocket.NewMux(map[string]interface{}{
		"mix":   c.sendConvoOnion,
		"reply": c.openReplyOnion,
		"error": c.convoRoundError,
	})
}

func (c *Client) convoRoundError(conn typesocket.Conn, v coordinator.RoundError) {
	log.WithFields(log.Fields{"round": v.Round}).Errorf("round error: %s", v.Err)
}

func (c *Client) sendConvoOnion(conn typesocket.Conn, v coordinator.MixRound) {
	round := v.MixSettings.Round

	for i, mixKey := range c.Mixers {
		if !v.MixSettings.Verify(mixKey, v.MixSignatures[i]) {
			log.WithFields(log.Fields{"round": round, "mixer": i}).Error("failed to verify mixnet settings")
			return
		}
	}

	c.mu.Lock()
	roundHandler := c.convoHandler
	c.mu.Unlock()

	msg := roundHandler.NextMessage(round).Marshal()
	ctxt, keys := onionbox.Seal(msg, mixnet.ForwardNonce(round), v.MixSettings.OnionKeys)

	c.mu.Lock()
	c.rounds[round] = &roundState{
		Handler:   roundHandler,
		OnionKeys: keys,
	}
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
