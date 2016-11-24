package main

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	. "vuvuzela.io/vuvuzela"
)

func TestSoloConversation(t *testing.T) {
	public, private, err := GenerateBoxKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	convo := &Conversation{
		peerPublicKey: public,
		myPublicKey:   public,
		myPrivateKey:  private,
	}
	if convo.myRole() != convo.theirRole() {
		t.Fatalf("expecting roles to match")
	}

	msg := make([]byte, 256)
	rand.Read(msg)

	var round uint32 = 42
	ctxt := convo.Seal(msg, round, convo.myRole())
	xmsg, ok := convo.Open(ctxt, round, convo.theirRole())
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
