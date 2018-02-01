package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jroimartin/gocui"
	"golang.org/x/crypto/nacl/secretbox"

	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/log/ansi"
	"vuvuzela.io/vuvuzela/convo"
)

type Conversation struct {
	peerUsername string
	myUsername   string

	gc *GuiClient

	sync.RWMutex
	outQueue    chan []byte
	rounds      map[uint32]*convoRound
	pendingCall *keywheelStart

	sessionKey      *[32]byte
	sessionKeyRound uint32

	lastPeerResponding bool
	lastLatency        time.Duration
	lastRound          uint32
	unread             bool
	focused            bool
}

func (c *Conversation) Init() {
	c.outQueue = make(chan []byte, 64)
	c.lastPeerResponding = false
	c.rounds = make(map[uint32]*convoRound)
}

type convoRound struct {
	sentMessage []byte
	roundKey    *[32]byte
	created     time.Time
}

func (c *Conversation) ViewName() string {
	return c.peerUsername
}

type ConvoMessage struct {
	Body interface{}
	// seq/ack numbers can go here
}

type TextMessage struct {
	Message []byte
}

// TimestampMessages were previously used for computing end-to-end latency.
type TimestampMessage struct {
	Timestamp time.Time
}

func (cm *ConvoMessage) Marshal() (msg [convo.SizeMessageBody]byte) {
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

func (c *Conversation) QueueTextMessage(msg []byte) {
	var ok bool
	select {
	case c.outQueue <- msg:
		ok = true
	default:
		ok = false
	}

	if ok {
		c.Printf("%s %s\n", ansi.Colorf("<"+c.myUsername+">", ansi.Bold), msg)
	} else {
		c.Warnf("Queue full, message not sent to %s: %s\n", c.peerUsername, msg)
	}
}

func (c *Conversation) Printf(format string, args ...interface{}) {
	v, err := c.gc.gui.View(c.ViewName())
	if err != nil {
		return
	}

	fmt.Fprintf(v, format, args...)

	c.Lock()
	defer c.Unlock()
	if !c.focused {
		c.unread = true
	}
}

func (c *Conversation) PrintfSync(format string, args ...interface{}) {
	done := make(chan struct{})
	c.gc.gui.Update(func(g *gocui.Gui) error {
		defer close(done)

		v, err := g.View(c.ViewName())
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(v, format, args...)

		return err
	})
	<-done

	c.Lock()
	defer c.Unlock()
	if !c.focused {
		c.unread = true
	}
}

func (c *Conversation) Warnf(format string, args ...interface{}) {
	c.Printf("-!- "+format, args...)
}

func (c *Conversation) WarnfSync(format string, args ...interface{}) {
	c.PrintfSync("-!- "+format, args...)
}

func (c *Conversation) NextMessage(round uint32) *convo.DeadDropMessage {
	c.Lock()
	c.lastRound = round
	c.Unlock()
	// update the round number in the status bar
	go c.gc.redraw()

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

	roundKey := c.rollAndReplaceKey(round)
	if roundKey == nil {
		// We've rolled past this round so generate cover traffic.
		dummy := new(convo.DeadDropMessage)
		rand.Read(dummy.EncryptedMessage[:])
		return dummy
	}
	ctxt := c.Seal(msgdata[:], round, roundKey)

	var encmsg [convo.SizeEncryptedMessageBody]byte
	copy(encmsg[:], ctxt)

	c.Lock()
	c.rounds[round] = &convoRound{
		sentMessage: encmsg[:],
		roundKey:    roundKey,
		created:     time.Now(),
	}
	c.Unlock()

	return &convo.DeadDropMessage{
		DeadDrop:         c.deadDrop(round, roundKey),
		EncryptedMessage: encmsg,
	}
}

func (c *Conversation) Reply(round uint32, encmsg []byte) {
	rlog := log.WithFields(log.Fields{"round": round})

	var responding bool
	defer func() {
		c.Lock()
		c.lastPeerResponding = responding
		c.Unlock()
		c.gc.redraw()
	}()

	c.Lock()
	st, ok := c.rounds[round]
	delete(c.rounds, round)
	// Delete old rounds to ensure forward secrecy.
	for r := range c.rounds {
		if r < round-10 {
			delete(c.rounds, r)
		}
	}
	c.Unlock()
	if !ok {
		rlog.Error("round not found")
		return
	}

	if bytes.Compare(encmsg, st.sentMessage) == 0 && !c.Solo() {
		return
	}

	msgdata, ok := c.Open(encmsg, round, st.roundKey)
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
	c.Lock()
	c.lastLatency = time.Now().Sub(st.created)
	c.Unlock()

	switch m := msg.Body.(type) {
	case *TextMessage:
		s := strings.TrimRight(string(m.Message), "\x00")
		c.PrintfSync("<%s> %s\n", c.peerUsername, s)
		seldomNotify("%s says: %s", c.peerUsername, s)
	case *TimestampMessage:
		// ignore it
	}
}

type Status struct {
	PeerResponding bool
	Round          uint32
	Latency        float64
	Unread         bool
}

func (c *Conversation) Status() *Status {
	c.RLock()
	status := &Status{
		PeerResponding: c.lastPeerResponding,
		Round:          c.lastRound,
		Latency:        float64(c.lastLatency) / float64(time.Second),
		Unread:         c.unread,
	}
	c.RUnlock()
	return status
}

func (c *Conversation) Solo() bool {
	return c.peerUsername == c.myUsername
}

func (c *Conversation) Seal(message []byte, round uint32, roundKey *[32]byte) []byte {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[:], round)
	nameHash := sha256.Sum256([]byte(c.peerUsername))
	copy(nonce[4:], nameHash[:16])

	ctxt := secretbox.Seal(nil, message, &nonce, roundKey)
	return ctxt
}

func (c *Conversation) Open(ctxt []byte, round uint32, roundKey *[32]byte) ([]byte, bool) {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[:], round)
	nameHash := sha256.Sum256([]byte(c.myUsername))
	copy(nonce[4:], nameHash[:16])

	return secretbox.Open(nil, ctxt, &nonce, roundKey)
}

type keywheelStart struct {
	sessionKey *[32]byte
	convoRound uint32
}

func (c *Conversation) rollAndReplaceKey(targetRound uint32) *[32]byte {
	c.Lock()
	key, keyRound := c.sessionKey, c.sessionKeyRound
	c.Unlock()

	newKey := rollKey(key, keyRound, targetRound)
	if newKey == nil {
		return nil
	}

	c.Lock()
	c.sessionKey, c.sessionKeyRound = newKey, targetRound
	c.Unlock()

	return newKey
}

func rollKey(currentKey *[32]byte, keyRound, targetRound uint32) *[32]byte {
	if keyRound > targetRound {
		return nil
	}

	newKey := new([32]byte)
	copy(newKey[:], currentKey[:])

	hash := sha512.New512_256()
	key := newKey[:]
	for r := keyRound; r < targetRound; r++ {
		hash.Reset()
		binary.Write(hash, binary.BigEndian, r)
		hash.Write(key)
		key = hash.Sum(key[:0])
	}

	return newKey
}

// roundSyncer is used to agree on a past convo round, which is used to
// bootstrap a convo's keywheel for forward secrecy. The sender calls
// outgoingCallConvoRound and the receiver calls incomingCallConvoRound.
// For 0 <= X <= roundingIncrement, the following should hold:
//   agreedRoundSender, intent := outgoingCallConvoRound(r)
//   agreedRoundReceiver := incomingCallConvoRound(r+X, intent)
//   agreedRoundSender == agreedRoundReceiver
type roundSyncer struct {
	roundingIncrement uint32
}

var stdRoundSyncer = roundSyncer{
	roundingIncrement: 10000,
}

func (rs roundSyncer) outgoingCallConvoRound(latestRound uint32) (round uint32, intent int) {
	return rs.epochStart(latestRound)
}

func (rs roundSyncer) incomingCallConvoRound(latestRound uint32, intent int) uint32 {
	epochStart, currIntent := rs.epochStart(latestRound)
	if currIntent == intent {
		return epochStart
	}
	return epochStart - rs.roundingIncrement
}

func (rs roundSyncer) epochStart(round uint32) (uint32, int) {
	c := rs.roundingIncrement
	intent := int((round / c) % 2)
	return round / c * c, intent
}

func (c *Conversation) deadDrop(round uint32, roundKey *[32]byte) (id convo.DeadDrop) {
	h := hmac.New(sha256.New, roundKey[:])
	h.Write([]byte("DeadDrop"))
	binary.Write(h, binary.BigEndian, round)
	r := h.Sum(nil)
	copy(id[:], r)
	return
}
