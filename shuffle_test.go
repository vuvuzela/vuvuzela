package vuvuzela

import (
	"testing"

	"github.com/davidlazar/vuvuzela/rand"
)

func TestShuffle(t *testing.T) {
	n := 64
	x := make([][]byte, n)
	for i := 0; i < n; i++ {
		x[i] = []byte{byte(i)}
	}

	s := NewShuffler(rand.Reader, len(x))
	s.Shuffle(x)

	allSame := true
	for i := 0; i < n; i++ {
		if x[i][0] != byte(i) {
			allSame = false
		}
	}

	if allSame {
		t.Errorf("shuffler isn't shuffling")
	}

	s.Unshuffle(x)

	for i := 0; i < n; i++ {
		if x[i][0] != byte(i) {
			t.Errorf("unshuffle does not undo shuffle")
			break
		}
	}
}
