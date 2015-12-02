package vuvuzela

import (
	"encoding/binary"
	"math"

	"github.com/davidlazar/vuvuzela/rand"
)

func laplace(mu, b float64) float64 {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}

	x := binary.BigEndian.Uint64(r[:])
	u := float64(x)/float64(^uint64(0)) - .5

	var abs, sign float64
	if u < 0 {
		abs = -u
		sign = -1
	} else {
		abs = u
		sign = 1
	}

	return mu - b*sign*math.Log(1-2*abs)
}

func cappedFlooredLaplace(mu, b float64) int {
	x := laplace(mu, b)
	if x < 0 {
		return cappedFlooredLaplace(mu, b)
	}

	return int(x)
}
