package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/nacl/secretbox"

	"vuvuzela.io/crypto/onionbox"
	. "vuvuzela.io/vuvuzela"
)

type Conversation struct {
	sync.RWMutex

	pki          *PKI
	myUsername   string
	peerUsername string
	secretKey    *[32]byte

	gui *GuiClient

	outQueue      chan []byte
	pendingRounds map[uint32]*pendingRound

	lastPeerResponding bool
	lastLatency        time.Duration
	lastRound          uint32
}

func (c *Conversation) Init() {
	c.Lock()
	c.outQueue = make(chan []byte, 64)
	c.pendingRounds = make(map[uint32]*pendingRound)
	c.lastPeerResponding = false
	c.Unlock()
}

type pendingRound struct {
	onionSharedKeys []*[32]byte
	sentMessage     [SizeEncryptedMessage]byte
}

type ConvoMessage struct {
	Body interface{}
	// seq/ack numbers can go here
}

type TextMessage struct {
	Message []byte
}

type TimestampMessage struct {
	Timestamp time.Time
}

func (cm *ConvoMessage) Marshal() (msg [SizeMessage]byte) {
	switch v := cm.Body.(type) {
	case *TimestampMessage:
		msg[0] = 0
		binary.PutVarint(msg[1:], v.Timestamp.Unix())
	case *TextMessage:
		msg[0] = 1
		copy(msg[1:], v.Message)
	}
	return
}

func (cm *ConvoMessage) Unmarshal(msg []byte) error {
	switch msg[0] {
	case 0:
		ts, _ := binary.Varint(msg[1:])
		cm.Body = &TimestampMessage{
			Timestamp: time.Unix(ts, 0),
		}
	case 1:
		cm.Body = &TextMessage{msg[1:]}
	default:
		return fmt.Errorf("unexpected message type: %d", msg[0])
	}
	return nil
}

func (c *Conversation) QueueTextMessage(msg []byte) bool {
	select {
	case c.outQueue <- msg:
		return true
	default:
		return false
	}
}

func (c *Conversation) NextConvoRequest(round uint32) *ConvoRequest {
	c.Lock()
	c.lastRound = round
	c.Unlock()
	go c.gui.Flush()

	var body interface{}

	select {
	case m := <-c.outQueue:
		body = &TextMessage{Message: m}
	default:
		body = &TimestampMessage{
			Timestamp: time.Now(),
		}
	}
	msg := &ConvoMessage{
		Body: body,
	}
	msgdata := msg.Marshal()

	var encmsg [SizeEncryptedMessage]byte
	ctxt := c.Seal(msgdata[:], round)
	copy(encmsg[:], ctxt)

	exchange := &ConvoExchange{
		DeadDrop:         c.deadDrop(round),
		EncryptedMessage: encmsg,
	}

	onion, sharedKeys := onionbox.Seal(exchange.Marshal(), ForwardNonce(round), c.pki.ServerKeys().Keys())

	pr := &pendingRound{
		onionSharedKeys: sharedKeys,
		sentMessage:     encmsg,
	}
	c.Lock()
	c.pendingRounds[round] = pr
	c.Unlock()

	return &ConvoRequest{
		Round: round,
		Onion: onion,
	}
}

func (c *Conversation) HandleConvoResponse(r *ConvoResponse) {
	rlog := log.WithFields(log.Fields{"round": r.Round})

	var responding bool
	defer func() {
		c.Lock()
		c.lastPeerResponding = responding
		c.Unlock()
		c.gui.Flush()
	}()

	c.Lock()
	pr, ok := c.pendingRounds[r.Round]
	delete(c.pendingRounds, r.Round)
	c.Unlock()
	if !ok {
		rlog.Error("round not found")
		return
	}

	encmsg, ok := onionbox.Open(r.Onion, BackwardNonce(r.Round), pr.onionSharedKeys)
	if !ok {
		rlog.Error("decrypting onion failed")
		return
	}

	if bytes.Compare(encmsg, pr.sentMessage[:]) == 0 && !c.Solo() {
		return
	}

	msgdata, ok := c.Open(encmsg, r.Round)
	if !ok {
		rlog.Error("decrypting peer message failed")
		return
	}

	msg := new(ConvoMessage)
	if err := msg.Unmarshal(msgdata); err != nil {
		rlog.Error("unmarshaling peer message failed")
		return
	}

	responding = true

	switch m := msg.Body.(type) {
	case *TextMessage:
		s := strings.TrimRight(string(m.Message), "\x00")
		c.gui.Printf("<%s> %s\n", c.peerUsername, s)
	case *TimestampMessage:
		latency := time.Now().Sub(m.Timestamp)
		c.Lock()
		c.lastLatency = latency
		c.Unlock()
	}
}

type Status struct {
	PeerResponding bool
	Round          uint32
	Latency        float64
}

func (c *Conversation) Status() *Status {
	c.RLock()
	status := &Status{
		PeerResponding: c.lastPeerResponding,
		Round:          c.lastRound,
		Latency:        float64(c.lastLatency) / float64(time.Second),
	}
	c.RUnlock()
	return status
}

func (c *Conversation) Solo() bool {
	return c.peerUsername == c.myUsername
}

func (c *Conversation) Seal(message []byte, round uint32) []byte {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[:], round)
	nameHash := sha256.Sum256([]byte(c.peerUsername))
	copy(nonce[4:], nameHash[:16])

	ctxt := secretbox.Seal(nil, message, &nonce, c.secretKey)
	return ctxt
}

func (c *Conversation) Open(ctxt []byte, round uint32) ([]byte, bool) {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[:], round)
	nameHash := sha256.Sum256([]byte(c.myUsername))
	copy(nonce[4:], nameHash[:16])

	return secretbox.Open(nil, ctxt, &nonce, c.secretKey)
}

func (c *Conversation) deadDrop(round uint32) (id DeadDrop) {
	h := hmac.New(sha256.New, c.secretKey[:])
	h.Write([]byte("DeadDrop"))
	binary.Write(h, binary.BigEndian, round)
	r := h.Sum(nil)
	copy(id[:], r)
	return
}
