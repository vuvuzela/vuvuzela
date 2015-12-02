package vuvuzela

import (
	"encoding/binary"

	. "github.com/davidlazar/vuvuzela/internal"
	"github.com/davidlazar/vuvuzela/onionbox"
	"github.com/davidlazar/vuvuzela/rand"
)

func FillWithFakeSingles(dest [][]byte, nonce *[24]byte, nextKeys []*[32]byte) {
	ParallelFor(len(dest), func(p *P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var exchange [SizeConvoExchange]byte
			rand.Read(exchange[:])
			onion, _ := onionbox.Seal(exchange[:], nonce, nextKeys)
			dest[i] = onion
		}
	})
}

func FillWithFakeDoubles(dest [][]byte, nonce *[24]byte, nextKeys []*[32]byte) {
	ParallelFor(len(dest)/2, func(p *P) {
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

func FillWithFakeIntroductions(dest [][]byte, noiseCounts []int, nonce *[24]byte, nextKeys []*[32]byte) {
	buckets := make([]int, len(dest))
	idx := 0
	for b, count := range noiseCounts {
		for i := 0; i < count; i++ {
			buckets[idx] = b
			idx++
		}
	}

	ParallelFor(len(dest), func(p *P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var exchange [SizeDialExchange]byte
			binary.BigEndian.PutUint32(exchange[0:4], uint32(buckets[i]))
			rand.Read(exchange[4:])
			onion, _ := onionbox.Seal(exchange[:], nonce, nextKeys)
			dest[i] = onion
		}
	})
}
