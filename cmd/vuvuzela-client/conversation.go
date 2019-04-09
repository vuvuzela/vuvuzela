// Copyright 2015 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

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

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/log/ansi"
	"vuvuzela.io/vuvuzela/convo"
)

type Conversation struct {
	peerUsername string
	myUsername   string

	gc *GuiClient

	sync.RWMutex
	rounds      map[uint32]*convoRound
	pendingCall *keywheelStart

	outQueue    []seqMsg
	lastOut     int
	inQueue     map[uint32][]byte // seq number -> msg
	relativeSeq uint32
	seqBase     uint32
	ack         uint32

	sessionKey      *[32]byte
	sessionKeyRound uint32

	lastPeerResponding bool
	lastLatency        time.Duration
	lastRound          uint32
	unread             bool
	focused            bool
}

type seqMsg struct {
	RelativeSeq uint32
	Msg         []byte
}

func (c *Conversation) Init() {
	c.relativeSeq = 0
	c.seqBase = 0
	c.lastPeerResponding = false
	c.rounds = make(map[uint32]*convoRound)
	c.inQueue = make(map[uint32][]byte)
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
	Seq      uint32
	Ack      uint32
	Lowest   bool
	UserText []byte // Must be SizeUserText bytes.
}

const SizeUserText = convo.SizeMessageBody - 4 - 4 - 1

func (cm *ConvoMessage) Marshal() (msg [convo.SizeMessageBody]byte) {
	binary.BigEndian.PutUint32(msg[0:4], cm.Seq)
	binary.BigEndian.PutUint32(msg[4:8], cm.Ack)
	if cm.Lowest {
		msg[8] = 1
	} else {
		msg[8] = 0
	}
	copy(msg[9:], cm.UserText)
	return
}

func (cm *ConvoMessage) Unmarshal(msg []byte) error {
	if len(msg) != convo.SizeMessageBody {
		return errors.New("bad message length: want %d bytes, got %d", convo.SizeMessageBody, len(msg))
	}
	cm.Seq = binary.BigEndian.Uint32(msg[0:4])
	cm.Ack = binary.BigEndian.Uint32(msg[4:8])
	if msg[8] == 0 {
		cm.Lowest = false
	} else {
		cm.Lowest = true
	}
	cm.UserText = msg[9:]
	return nil
}

func (c *Conversation) QueueTextMessage(msg []byte) {
	c.Lock()
	c.outQueue = append(c.outQueue, seqMsg{
		RelativeSeq: c.relativeSeq,
		Msg:         msg,
	})
	c.relativeSeq++
	c.Unlock()

	// TODO print only SizeMessage bytes, so user knows what got truncated.
	c.Printf("%s\n", c.formatUserMessage(true, string(msg)))
}

func (c *Conversation) formatUserMessage(fromMe bool, msg string) string {
	max := len(c.myUsername)
	if n := len(c.peerUsername); n > max {
		max = n
	}
	max += 1

	username := c.peerUsername
	var usernameColor []ansi.Code
	if fromMe {
		username = c.myUsername
		usernameColor = []ansi.Code{ansi.Bold}
	}
	pad := strings.Repeat(" ", max-len(username))

	return fmt.Sprintf("%s%s %s %s", pad, ansi.Colorf(username, usernameColor...), ansi.Colorf("|", ansi.Foreground(27)), msg)
}

func (c *Conversation) Printf(format string, args ...interface{}) {
	v, err := c.gc.gui.View(c.ViewName())
	if err != nil {
		return
	}

	fmt.Fprintf(v, "%s ", ansi.Colorf(time.Now().Format("15:04:05"), ansi.Foreground(8)))
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

		fmt.Fprintf(v, "%s ", ansi.Colorf(time.Now().Format("15:04:05"), ansi.Foreground(8)))
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
	c.Printf(warningPrefix+format, args...)
}

func (c *Conversation) WarnfSync(format string, args ...interface{}) {
	c.PrintfSync(warningPrefix+format, args...)
}

func (c *Conversation) NextMessage(round uint32) *convo.DeadDropMessage {
	c.Lock()
	c.lastRound = round
	c.Unlock()
	// update the round number in the status bar
	go c.gc.redraw()

	c.Lock()

	// Cover traffic message by default
	msg := &ConvoMessage{
		Seq:      0,
		Ack:      c.ack,
		Lowest:   false,
		UserText: make([]byte, SizeUserText),
	}

	if len(c.outQueue) > 0 {
		if c.seqBase == 0 {
			// Use the conversation round as an initial seq#
			// to avoid seq# duplicates across client restart
			c.seqBase = round + 1
		}

		if c.lastOut != -1 && c.lastOut+1 < len(c.outQueue) {
			c.lastOut++
		} else {
			c.lastOut = 0
			msg.Lowest = true
		}

		msg.Seq = c.outQueue[c.lastOut].RelativeSeq + c.seqBase
		msg.UserText = c.outQueue[c.lastOut].Msg
	}
	c.Unlock()

	msgdata := msg.Marshal()

	roundKey := c.rollAndReplaceKey(round)
	if roundKey == nil {
		// We've rolled past this round so generate cover traffic.
		dummy := new(convo.DeadDropMessage)
		rand.Read(dummy.DeadDrop[:])
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

	newOutQueue := c.outQueue[:0]
	for _, out := range c.outQueue {
		if c.seqBase > 0 && out.RelativeSeq+c.seqBase <= msg.Ack {
			// We removed something from the queue, adjust lastOut.
			if c.lastOut > 0 {
				c.lastOut -= 1
			}
			continue
		}
		newOutQueue = append(newOutQueue, out)
	}
	c.outQueue = newOutQueue

	var displayMsgs [][]byte
	if msg.Seq > c.ack {
		// This message is not cover traffic (msg.Seq != 0) and we have
		// not processed it yet (msg.Seq > c.ack).  Queue the message.
		c.inQueue[msg.Seq] = msg.UserText

		// If this is the lowest-numbered message the peer knows about,
		// then don't bother waiting for any lower-numbered messages.
		if msg.Lowest {
			c.ack = msg.Seq - 1
		}

		// Acknowledge the longest consecutive chain starting from our
		// current ack value.
		i := c.ack + 1

		for {
			in, ok := c.inQueue[i]
			if !ok {
				break
			}
			displayMsgs = append(displayMsgs, in)
			delete(c.inQueue, i)
			c.ack = i
			i++
		}
	}
	c.Unlock()

	for _, body := range displayMsgs {
		s := strings.TrimRight(string(body), "\x00")
		c.PrintfSync("%s\n", c.formatUserMessage(false, s))
		seldomNotify("%s says: %s", c.peerUsername, s)
	}
}

type Status struct {
	PeerResponding bool
	Round          uint32
	Latency        float64
	Unread         bool
	Unacked        int
}

func (c *Conversation) Status() *Status {
	c.RLock()
	status := &Status{
		PeerResponding: c.lastPeerResponding,
		Round:          c.lastRound,
		Latency:        float64(c.lastLatency) / float64(time.Second),
		Unread:         c.unread,
		Unacked:        len(c.outQueue),
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
