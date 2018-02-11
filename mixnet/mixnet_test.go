// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/internal/mock"
	"vuvuzela.io/vuvuzela/mixnet"
)

func TestMixnet(t *testing.T) {
	coordinatorPublic, coordinatorPrivate, _ := ed25519.GenerateKey(rand.Reader)

	mixchain := mock.LaunchMixchain(3, coordinatorPublic)

	coordinatorLoop(coordinatorPrivate, mixchain)
}

func coordinatorLoop(coordinatorKey ed25519.PrivateKey, mixchain *mock.Mixchain) {
	coordinatorClient := &mixnet.Client{
		Key: coordinatorKey,
	}

	for round := uint32(1); round < 10; round++ {
		settings := &mixnet.RoundSettings{
			Service: "Convo",
			Round:   round,
		}
		sigs, err := coordinatorClient.NewRound(context.Background(), mixchain.Servers, settings)
		if err != nil {
			log.Fatalf("mixnet.NewRound: %s", err)
		}
		settingsMsg := settings.SigningMessage()
		for i, sig := range sigs {
			if !ed25519.Verify(mixchain.Servers[i].Key, settingsMsg, sig) {
				log.Fatalf("failed to verify round settings from mixer %d", i+1)
			}
		}

		messages, onions, onionKeys := makeConvoOnions(settings)
		replies, err := coordinatorClient.RunRound(context.Background(), mixchain.Servers[0], "Convo", round, onions)
		if err != nil {
			log.Fatalf("mixnet.RunRound: %s", err)
		}

		if len(replies) != len(onions) {
			log.Fatalf("unexpected number of reply onions: got %d, want %d", len(replies), len(onions))
		}

		// Alice and Bob swap messages; Charlie gets his own message back.
		messages[0], messages[1] = messages[1], messages[0]

		nonce := mixnet.BackwardNonce(settings.Round)
		for i, onion := range replies {
			msg, ok := onionbox.Open(onion, nonce, onionKeys[i])
			if !ok {
				log.Fatalf("failed to open reply onion at position %d", i)
			}
			if !bytes.Equal(msg, messages[i]) {
				log.Fatalf("unexpected message at position %d", i)
			}
		}
	}
}

func makeConvoOnions(settings *mixnet.RoundSettings) (messages [][]byte, onions [][]byte, onionKeys [][]*[32]byte) {
	msgAlice := &convo.DeadDropMessage{}
	msgBob := &convo.DeadDropMessage{}
	rand.Read(msgAlice.DeadDrop[:])
	rand.Read(msgAlice.EncryptedMessage[:])
	rand.Read(msgBob.EncryptedMessage[:])
	// Assume Alice is talking to Bob.
	copy(msgBob.DeadDrop[:], msgAlice.DeadDrop[:])

	// Charlie is connected but not talking to anyone.
	msgCharlie := &convo.DeadDropMessage{}
	rand.Read(msgCharlie.DeadDrop[:])
	rand.Read(msgCharlie.EncryptedMessage[:])

	messages = make([][]byte, 3)
	onions = make([][]byte, 3)
	onionKeys = make([][]*[32]byte, 3)

	nonce := mixnet.ForwardNonce(settings.Round)
	for i, ddmsg := range []*convo.DeadDropMessage{msgAlice, msgBob, msgCharlie} {
		messages[i] = ddmsg.EncryptedMessage[:]
		onions[i], onionKeys[i] = onionbox.Seal(ddmsg.Marshal(), nonce, settings.OnionKeys)
	}

	return
}

func TestAuth(t *testing.T) {
	coordinatorPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, badPrivate, _ := ed25519.GenerateKey(rand.Reader)

	mixchain := mock.LaunchMixchain(3, coordinatorPublic)

	badClient := &mixnet.Client{
		Key: badPrivate,
	}

	_, err := badClient.NewRound(context.Background(), mixchain.Servers, &mixnet.RoundSettings{
		Service: "Convo",
		Round:   42,
	})
	err = errors.Cause(err)
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("unexpected error: %s", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("unexpected status: %s", st)
	}
}

var chainLen = flag.Int("chainlen", 6, "chain length in TestLongerMixnet")
var numMsgs = flag.Int("numMsgs", 1000, "number of messages in TestLongerMixnet")

func TestMain(t *testing.T) {
	flag.Parse()
}

func TestMixnetPerformance(t *testing.T) {
	coordinatorPublic, coordinatorPrivate, _ := ed25519.GenerateKey(rand.Reader)

	mixchain := mock.LaunchMixchain(*chainLen, coordinatorPublic)

	coordinatorClient := &mixnet.Client{
		Key: coordinatorPrivate,
	}

	for round := uint32(1); round <= 2; round++ {
		settings := &mixnet.RoundSettings{
			Service: "Convo",
			Round:   round,
		}

		log.Warnf("Starting new round")
		sigs, err := coordinatorClient.NewRound(context.Background(), mixchain.Servers, settings)
		if err != nil {
			log.Fatalf("mixnet.NewRound: %s", err)
		}
		settingsMsg := settings.SigningMessage()
		for i, sig := range sigs {
			if !ed25519.Verify(mixchain.Servers[i].Key, settingsMsg, sig) {
				log.Fatalf("failed to verify round settings from mixer %d", i+1)
			}
		}

		log.Warnf("Generating onions")
		onions := make([][]byte, *numMsgs)
		onionKeys := make([][]*[32]byte, *numMsgs)
		lenMsg := len((&convo.DeadDropMessage{}).Marshal())
		nonce := mixnet.ForwardNonce(settings.Round)
		concurrency.ParallelFor(*numMsgs, func(p *concurrency.P) {
			for i, ok := p.Next(); ok; i, ok = p.Next() {
				msg := make([]byte, lenMsg)
				rand.Read(msg)
				onions[i], onionKeys[i] = onionbox.Seal(msg, nonce, settings.OnionKeys)
			}
		})

		log.Warnf("Running round")
		start := time.Now()
		replies, err := coordinatorClient.RunRound(context.Background(), mixchain.Servers[0], "Convo", round, onions)
		if err != nil {
			log.Fatalf("mixnet.RunRound: %s", err)
		}
		duration := time.Now().Sub(start)
		log.Warnf("RunRound took %s -- chainLen=%d  numMsgs=%d", duration, *chainLen, *numMsgs)

		if len(replies) != len(onions) {
			log.Fatalf("unexpected number of reply onions: got %d, want %d", len(replies), len(onions))
		}
	}
}

func BenchmarkDecryption(b *testing.B) {
	count := *numMsgs
	keys := make([]*[32]byte, count)
	concurrency.ParallelFor(count, func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			pub, _, _ := box.GenerateKey(rand.Reader)
			keys[i] = pub
		}
	})
	_, priv, _ := box.GenerateKey(rand.Reader)
	b.ResetTimer()

	for x := 0; x < b.N; x++ {
		concurrency.ParallelFor(count, func(p *concurrency.P) {
			var sharedKey [32]byte
			for i, ok := p.Next(); ok; i, ok = p.Next() {
				box.Precompute(&sharedKey, keys[i], priv)
			}
		})
	}
}
