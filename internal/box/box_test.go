package box

import (
	"crypto/rand"
	"golang.org/x/crypto/nacl/box"
	"testing"
)

func BenchmarkSeal(b *testing.B) {
	_, myPrivate, _ := box.GenerateKey(rand.Reader)
	theirPublic, _, _ := box.GenerateKey(rand.Reader)
	message := make([]byte, 256)
	nonce := new([24]byte)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		box.Seal(nil, message, nonce, theirPublic, myPrivate)
	}
}

func BenchmarkSealAfterPrecomputation(b *testing.B) {
	_, myPrivate, _ := box.GenerateKey(rand.Reader)
	theirPublic, _, _ := box.GenerateKey(rand.Reader)
	message := make([]byte, 256)
	nonce := new([24]byte)
	sharedKey := new([32]byte)
	box.Precompute(sharedKey, theirPublic, myPrivate)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		box.SealAfterPrecomputation(nil, message, nonce, sharedKey)
	}
}
