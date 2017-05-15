package mixnet

import (
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
)

func FillWithFakeSingles(dest [][]byte, nonce *[24]byte, nextKeys []*[32]byte) {
	concurrency.ParallelFor(len(dest), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var msg [sizeMixMessage]byte
			rand.Read(msg[:])
			onion, _ := onionbox.Seal(msg[:], nonce, nextKeys)
			dest[i] = onion
		}
	})
}

func FillWithFakeDoubles(dest [][]byte, nonce *[24]byte, nextKeys []*[32]byte) {
	concurrency.ParallelFor(len(dest)/2, func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var msg1 [sizeMixMessage]byte
			var msg2 [sizeMixMessage]byte
			rand.Read(msg1[:])
			copy(msg2[0:16], msg1[0:16])
			rand.Read(msg2[16:])
			onion1, _ := onionbox.Seal(msg1[:], nonce, nextKeys)
			onion2, _ := onionbox.Seal(msg2[:], nonce, nextKeys)
			dest[i*2] = onion1
			dest[i*2+1] = onion2
		}
	})
}
