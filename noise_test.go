package vuvuzela

import (
	"crypto/rand"
	"flag"
	"os"
	"runtime"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

var mu = 100000

const numKeys = 2

func BenchmarkFillWithFakeSingles(b *testing.B) {
	noise := make([][]byte, mu)
	keys := genKeys(numKeys)
	nonce := new([24]byte)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FillWithFakeSingles(noise, nonce, keys)
	}
}

func BenchmarkFillWithFakeDoubles(b *testing.B) {
	noise := make([][]byte, mu)
	keys := genKeys(numKeys)
	nonce := new([24]byte)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FillWithFakeDoubles(noise, nonce, keys)
	}
}

func TestMain(m *testing.M) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.IntVar(&mu, "mu", 100000, "mu value")
	flag.Parse()
	os.Exit(m.Run())
}

func genKeys(i int) []*[32]byte {
	keys := make([]*[32]byte, i)
	for i := range keys {
		pub, _, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		keys[i] = pub
	}
	return keys
}
