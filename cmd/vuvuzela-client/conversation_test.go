// Copyright 2015 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/davidlazar/go-crypto/encoding/base32"
)

func TestSoloConversation(t *testing.T) {
	convo := &Conversation{
		myUsername:      "alice@example.org",
		peerUsername:    "alice@example.org",
		sessionKey:      new([32]byte),
		sessionKeyRound: 23,
	}
	rand.Read(convo.sessionKey[:])

	msg := make([]byte, 256)
	rand.Read(msg)

	var round uint32 = 42
	convo.rollAndReplaceKey(round)
	ctxt := convo.Seal(msg, round, convo.sessionKey)
	xmsg, ok := convo.Open(ctxt, round, convo.sessionKey)
	if !ok {
		t.Fatalf("failed to decrypt message")
	}

	if bytes.Compare(msg, xmsg) != 0 {
		t.Fatalf("messages don't match")
	}
}

func TestMarshalConvoMessage(t *testing.T) {
	cm := &ConvoMessage{
		Seq:      55555,
		Ack:      22222,
		Lowest:   true,
		UserText: make([]byte, SizeUserText),
	}
	copy(cm.UserText, []byte("hello world"))
	data := cm.Marshal()

	xcm := new(ConvoMessage)
	if err := xcm.Unmarshal(data[:]); err != nil {
		t.Fatalf("Unmarshal error: %s", err)
	}

	if !reflect.DeepEqual(cm, xcm) {
		t.Fatalf("%#v != %#v", cm, xcm)
	}
}

func TestRollKey(t *testing.T) {
	k0 := new([32]byte)
	k1 := rollKey(k0, 0, 1)
	k2 := rollKey(k1, 1, 2)

	k2a := rollKey(k0, 0, 2)

	if !bytes.Equal(k2[:], k2a[:]) {
		t.Fatalf("%v != %v", k2, k2a)
	}

	k2strExpected := "8sjdg6x3a7g78293d5n470y20myqhj723bp0687637sdt89gkrq0"
	k2strActual := base32.EncodeToString(k2[:])
	if k2strActual != k2strExpected {
		t.Fatalf("got %q, want %q", k2strActual, k2strExpected)
	}
}

func TestSyncConvoRound(t *testing.T) {
	syncer := roundSyncer{
		roundingIncrement: 1000,
	}

	for i := uint32(0); i < 10000; i++ {
		out, intent := syncer.outgoingCallConvoRound(i)
		for j := i; j < i+1001; j++ {
			in := syncer.incomingCallConvoRound(j, intent)
			if out != in {
				t.Fatalf("i=%d -> out=%d intent=%d :: j=%d -> in=%d", i, out, intent, j, in)
			}
		}
	}
}
