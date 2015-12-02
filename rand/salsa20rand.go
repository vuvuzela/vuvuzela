package rand

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"sync"

	"golang.org/x/crypto/salsa20"
)

// TODO we should occasionally reseed the PRNG

type Salsa20Rand struct {
	zeroes       []byte
	buffer       []byte
	bufferOffset int

	key   [32]byte
	nonce uint64
}

func NewSalsa20Rand(base io.Reader) *Salsa20Rand {
	n := 16 * 1024

	sr := &Salsa20Rand{
		zeroes:       make([]byte, n),
		buffer:       make([]byte, n),
		bufferOffset: n,
		nonce:        0,
	}
	if n, err := base.Read(sr.key[:]); n != 32 || err != nil {
		panic("NewSalsa20Rand: " + err.Error())
	}
	sr.fill()
	return sr
}

func (sr *Salsa20Rand) Read(d []byte) (n int, err error) {
	for len(d) > 0 {
		if sr.bufferOffset == len(sr.buffer) {
			sr.fill()
		}

		m := copy(d, sr.buffer[sr.bufferOffset:])
		d = d[m:]
		sr.bufferOffset += m
		n += m
	}

	return
}

func (sr *Salsa20Rand) fill() {
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], sr.nonce)
	sr.nonce += 1

	salsa20.XORKeyStream(sr.buffer, sr.zeroes, nonce[:], &sr.key)
	sr.bufferOffset = 0
}

type MutexReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func NewMutexReader(reader io.Reader) io.Reader {
	return &MutexReader{
		reader: reader,
	}
}

func (mr *MutexReader) Read(d []byte) (n int, err error) {
	mr.mu.Lock()
	n, err = mr.reader.Read(d)
	mr.mu.Unlock()
	return
}

type PerCPUReader struct {
	readers []io.Reader
}

func NewPerCPUReader(initfunc func() io.Reader) io.Reader {
	readers := make([]io.Reader, runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		readers[i] = initfunc()
	}
	return &PerCPUReader{
		readers: readers,
	}
}

func (pcr *PerCPUReader) Read(d []byte) (n int, err error) {
	thiscpu := cpu()
	return pcr.readers[thiscpu%uint64(runtime.NumCPU())].Read(d)
}

var Reader = NewPerCPUReader(func() io.Reader {
	return NewMutexReader(NewSalsa20Rand(rand.Reader))
})

func Read(b []byte) (n int, err error) {
	return io.ReadFull(Reader, b)
}
