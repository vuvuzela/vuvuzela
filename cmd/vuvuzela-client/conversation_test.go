package main

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestSoloConversation(t *testing.T) {
	convo := &Conversation{
		myUsername:   "alice@example.org",
		peerUsername: "alice@example.org",
		secretKey:    new([32]byte),
	}
	rand.Read(convo.secretKey[:])

	msg := make([]byte, 256)
	rand.Read(msg)

	var round uint32 = 42
	ctxt := convo.Seal(msg, round)
	xmsg, ok := convo.Open(ctxt, round)
	if !ok {
		t.Fatalf("failed to decrypt message")
	}

	if bytes.Compare(msg, xmsg) != 0 {
		t.Fatalf("messages don't match")
	}
}

func TestMarshalConvoMessage(t *testing.T) {
	now := time.Now()
	tsm := &TimestampMessage{Timestamp: now}
	cm := &ConvoMessage{Body: tsm}
	data := cm.Marshal()

	xcm := new(ConvoMessage)
	if err := xcm.Unmarshal(data[:]); err != nil {
		t.Fatalf("Unmarshal error: %s", err)
	}

	xtsm := xcm.Body.(*TimestampMessage)
	if xtsm.Timestamp.Unix() != now.Unix() {
		t.Fatalf("timestamps don't match")
	}
}
