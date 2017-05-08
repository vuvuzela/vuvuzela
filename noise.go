package vuvuzela

import (
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
)

func FillWithFakeSingles(dest [][]byte, nonce *[24]byte, nextKeys []*[32]byte) {
	concurrency.ParallelFor(len(dest), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var exchange [SizeConvoExchange]byte
			rand.Read(exchange[:])
			onion, _ := onionbox.Seal(exchange[:], nonce, nextKeys)
			dest[i] = onion
		}
	})
}

func FillWithFakeDoubles(dest [][]byte, nonce *[24]byte, nextKeys []*[32]byte) {
	concurrency.ParallelFor(len(dest)/2, func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var exchange1 [SizeConvoExchange]byte
			var exchange2 [SizeConvoExchange]byte
			rand.Read(exchange1[:])
			copy(exchange2[0:16], exchange1[0:16])
			rand.Read(exchange2[16:])
			onion1, _ := onionbox.Seal(exchange1[:], nonce, nextKeys)
			onion2, _ := onionbox.Seal(exchange2[:], nonce, nextKeys)
			dest[i*2] = onion1
			dest[i*2+1] = onion2
		}
	})
}
