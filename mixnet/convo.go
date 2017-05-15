package mixnet

import (
	"fmt"
	"unsafe"

	"golang.org/x/crypto/nacl/box"
)

type DeadDrop [16]byte

const (
	SizeMessageBody          = 240
	SizeEncryptedMessageBody = SizeMessageBody + box.Overhead
	sizeMixMessage           = int(unsafe.Sizeof(MixMessage{}))
)

type MixMessage struct {
	DeadDrop         DeadDrop
	EncryptedMessage [SizeEncryptedMessageBody]byte
}

func (m *MixMessage) Marshal() []byte {
	data := make([]byte, sizeMixMessage)
	copy(data[:16], m.DeadDrop[:])
	copy(data[16:], m.EncryptedMessage[:])
	return data
}

func (m *MixMessage) Unmarshal(data []byte) error {
	if len(data) != sizeMixMessage {
		return fmt.Errorf("wrong size: got %d, want %d", len(data), sizeMixMessage)
	}
	copy(m.DeadDrop[:], data[:16])
	copy(m.EncryptedMessage[:], data[16:])
	return nil
}
