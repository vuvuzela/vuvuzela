package rand

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	mrand "math/rand"
	"os"
	"testing"
	"time"
)

type zeroReader struct{}

func (zr *zeroReader) Read(d []byte) (n int, err error) {
	for i := range d {
		d[i] = 0
	}
	return len(d), nil
}

func TestRandomReads(t *testing.T) {
	rest := 1024 * 1024
	hash := sha256.New()
	srand := NewSalsa20Rand(new(zeroReader))

	mrand.Seed(time.Now().Unix())
	for rest > 0 {
		n := mrand.Intn(1024)
		if n > rest {
			n = rest
		}

		d := make([]byte, n)
		if _, err := srand.Read(d); err != nil {
			t.Fatalf("error: %s", err)
		}

		hash.Write(d)
		rest -= n
	}

	sum := hash.Sum(nil)
	expected := "12ccf37d07f2a467350971bbb7e83fe198f96bdd94b302ac52b100f330a466d8"
	actually := fmt.Sprintf("%x", sum)
	if actually != expected {
		t.Fatalf("\nexpected: %s\nactually: %s", expected, actually)
	}
}

const total = 100 * 1024 * 1024

func BenchmarkCryptoRand(b *testing.B) {
	x := make([]byte, total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rand.Read(x); err != nil {
			panic(err)
		}
	}
}

func BenchmarkBufioRand(b *testing.B) {
	x := make([]byte, total)
	buf := bufio.NewReader(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := buf.Read(x); err != nil {
			panic(err)
		}
	}
}

func BenchmarkDevUrandom(b *testing.B) {
	x := make([]byte, total)
	f, err := os.Open("/dev/urandom")
	if err != nil {
		panic(err)
	}
	buf := bufio.NewReader(f)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := buf.Read(x); err != nil {
			panic(err)
		}
	}
}

func BenchmarkVuvuzelaRand(b *testing.B) {
	x := make([]byte, total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Read(x); err != nil {
			panic(err)
		}
	}
}

func BenchmarkFasterRand(b *testing.B) {
	x := make([]byte, total)
	b.ResetTimer()
	fr := NewSalsa20Rand(Reader)
	for i := 0; i < b.N; i++ {
		if _, err := fr.Read(x); err != nil {
			panic(err)
		}
	}
}
