// Copyright 2015 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package convo

import (
	"fmt"
	"unsafe"

	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/vuvuzela/mixnet"
)

const (
	SizeMessageBody          = 240
	SizeEncryptedMessageBody = SizeMessageBody + box.Overhead
	sizeDeadDropMessage      = int(unsafe.Sizeof(DeadDropMessage{}))
)

type DeadDrop [16]byte

type DeadDropMessage struct {
	DeadDrop         DeadDrop
	EncryptedMessage [SizeEncryptedMessageBody]byte
}

func (m *DeadDropMessage) Marshal() []byte {
	data := make([]byte, sizeDeadDropMessage)
	copy(data[:16], m.DeadDrop[:])
	copy(data[16:], m.EncryptedMessage[:])
	return data
}

func (m *DeadDropMessage) Unmarshal(data []byte) error {
	if len(data) != sizeDeadDropMessage {
		return fmt.Errorf("wrong size: got %d, want %d", len(data), sizeDeadDropMessage)
	}
	copy(m.DeadDrop[:], data[:16])
	copy(m.EncryptedMessage[:], data[16:])
	return nil
}

type ConvoService struct {
	Laplace      rand.Laplace
	AccessCounts chan AccessCount
}

type AccessCount struct {
	Singles int64
	Doubles int64
}

func (s *ConvoService) SizeIncomingMessage() int {
	return sizeDeadDropMessage
}

func (s *ConvoService) SizeReplyMessage() int {
	return SizeEncryptedMessageBody
}

func (s *ConvoService) GenerateNoise(round uint32, nextServerKeys []*[32]byte) [][]byte {
	nonce := mixnet.ForwardNonce(round)

	numFakeSingles := s.Laplace.Uint32()
	numFakeDoubles := s.Laplace.Uint32()
	numFakeDoubles += numFakeDoubles % 2 // ensure numFakeDoubles is even
	noise := make([][]byte, numFakeSingles+numFakeDoubles)

	FillWithFakeSingles(noise[:numFakeSingles], nonce, nextServerKeys)
	FillWithFakeDoubles(noise[numFakeSingles:], nonce, nextServerKeys)

	return noise
}

func (s *ConvoService) SortReplies(incoming [][]byte) (replies [][]byte) {
	replies = make([][]byte, len(incoming))

	var singles, doubles int64
	var dest DeadDrop
	deadDrops := make(map[DeadDrop][]int)
	for i, msg := range incoming {
		copy(dest[:], msg[0:16])
		switch len(deadDrops[dest]) {
		case 0:
			singles++
			deadDrops[dest] = append(deadDrops[dest], i)
		case 1:
			singles--
			doubles++
			deadDrops[dest] = append(deadDrops[dest], i)
		}
	}

	concurrency.ParallelFor(len(replies), func(p *concurrency.P) {
		var dest DeadDrop
		var other int
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			msg := incoming[i]
			copy(dest[:], msg[0:16])
			drop := deadDrops[dest]
			if len(drop) == 1 {
				replies[i] = msg[16 : 16+SizeEncryptedMessageBody]
			}
			if len(drop) == 2 {
				if i == drop[0] {
					other = drop[1]
				} else {
					other = drop[0]
				}
				replies[i] = incoming[other][16 : 16+SizeEncryptedMessageBody]
			}
		}
	})

	counts := AccessCount{
		Singles: singles,
		Doubles: doubles,
	}
	select {
	case s.AccessCounts <- counts:
	default:
	}

	return
}
