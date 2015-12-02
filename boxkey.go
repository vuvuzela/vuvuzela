package vuvuzela

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/nacl/box"
)

type BoxKey [32]byte

func GenerateBoxKey(rand io.Reader) (publicKey, privateKey *BoxKey, err error) {
	pub, priv, err := box.GenerateKey(rand)
	return (*BoxKey)(pub), (*BoxKey)(priv), err
}

func (k *BoxKey) Key() *[32]byte {
	return (*[32]byte)(k)
}

func (k *BoxKey) String() string {
	return base32.EncodeToString(k[:])
}

func KeyFromString(s string) (*BoxKey, error) {
	key := new(BoxKey)
	b, err := base32.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base32 decode error: %s", err)
	}
	if copy(key[:], b) < 32 {
		return nil, fmt.Errorf("short key")
	}
	return key, nil
}

func (k *BoxKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *BoxKey) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	bs, err := base32.DecodeString(s)
	if err != nil {
		return fmt.Errorf("base32 decode error: %s", err)
	}
	if copy(k[:], bs) < 32 {
		return fmt.Errorf("short key")
	}
	return nil
}

type BoxKeys []*BoxKey

func (keys BoxKeys) Keys() []*[32]byte {
	xs := make([]*[32]byte, len(keys))
	for i := range keys {
		xs[i] = (*[32]byte)(keys[i])
	}
	return xs
}
