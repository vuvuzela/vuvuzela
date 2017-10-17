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

	"github.com/jroimartin/gocui"
	"golang.org/x/crypto/nacl/secretbox"

	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/vuvuzela/convo"
)

type Conversation struct {
	peerUsername string
	myUsername   string

	gc *GuiClient

	sync.RWMutex
	secretKey    *[32]byte
	outQueue     chan []byte
	sentMessages map[uint32][]byte
	pendingCall  interface{} // either an IncomingCall or OutgoingCall

	lastPeerResponding bool
	lastLatency        time.Duration
	lastRound          uint32
	unread             bool
	focused            bool
}

func (c *Conversation) Init() {
	c.outQueue = make(chan []byte, 64)
	c.lastPeerResponding = false
	c.sentMessages = make(map[uint32][]byte)
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
		c.Printf("<%s> %s\n", c.myUsername, msg)
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

	var encmsg [convo.SizeEncryptedMessageBody]byte
	ctxt := c.Seal(msgdata[:], round)
	copy(encmsg[:], ctxt)

	c.Lock()
	c.sentMessages[round] = encmsg[:]
	c.Unlock()

	return &convo.DeadDropMessage{
		DeadDrop:         c.deadDrop(round),
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
	sentMessage, ok := c.sentMessages[round]
	delete(c.sentMessages, round)
	c.Unlock()
	if !ok {
		rlog.Error("round not found")
		return
	}

	if bytes.Compare(encmsg, sentMessage) == 0 && !c.Solo() {
		return
	}

	msgdata, ok := c.Open(encmsg, round)
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
		c.PrintfSync("<%s> %s\n", c.peerUsername, s)
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

func (c *Conversation) deadDrop(round uint32) (id convo.DeadDrop) {
	h := hmac.New(sha256.New, c.secretKey[:])
	h.Write([]byte("DeadDrop"))
	binary.Write(h, binary.BigEndian, round)
	r := h.Sum(nil)
	copy(id[:], r)
	return
}
