package vuvuzela

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"golang.org/x/crypto/nacl/box"

	"github.com/davidlazar/vuvuzela/onionbox"
)

type DeadDrop [16]byte

const (
	SizeEncryptedMessage = SizeMessage + box.Overhead
	SizeConvoExchange    = int(unsafe.Sizeof(ConvoExchange{}))
	SizeEncryptedIntro   = int(unsafe.Sizeof(Introduction{})) + onionbox.Overhead
	SizeDialExchange     = int(unsafe.Sizeof(DialExchange{}))
)

type ConvoExchange struct {
	DeadDrop         DeadDrop
	EncryptedMessage [SizeEncryptedMessage]byte
}

func (e *ConvoExchange) Marshal() []byte {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, e); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (e *ConvoExchange) Unmarshal(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, e)
}

type Introduction struct {
	Rendezvous  uint32
	LongTermKey BoxKey
}

func (i *Introduction) Marshal() []byte {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, i); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (i *Introduction) Unmarshal(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, i)
}

type DialExchange struct {
	Bucket         uint32
	EncryptedIntro [SizeEncryptedIntro]byte
}

func (e *DialExchange) Marshal() []byte {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, e); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (e *DialExchange) Unmarshal(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, e)
}

func ForwardNonce(round uint32) *[24]byte {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[0:4], round)
	nonce[4] = 0
	return &nonce
}

func BackwardNonce(round uint32) *[24]byte {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[0:4], round)
	nonce[4] = 1
	return &nonce
}

func KeyDialBucket(key *BoxKey, buckets uint32) uint32 {
	return binary.BigEndian.Uint32(key[28:32])%buckets + 1
}
