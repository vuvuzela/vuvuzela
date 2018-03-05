// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet

import (
	"bytes"
	"encoding/json"

	"vuvuzela.io/alpenhorn/errors"
	pb "vuvuzela.io/vuvuzela/mixnet/convopb"
)

type RoundSettings struct {
	// Service is the name of the mixnet service.
	Service string

	// Round is the round that these settings correspond to.
	Round uint32

	// OnionKeys are the encryption keys in mixnet order.
	OnionKeys []*[32]byte

	// RawServiceData is the extra data required by the mixnet service.
	RawServiceData []byte

	// ServiceData is the result of parsing the RawServiceData;
	// it is not included in the signing message.
	ServiceData interface{} `json:"-"`
}

func (s RoundSettings) SigningMessage() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("RoundSettings")
	json.NewEncoder(buf).Encode(s)
	return buf.Bytes()
}

func (s *RoundSettings) FromProto(pbs *pb.RoundSettings) error {
	s.Service = pbs.Service
	s.Round = pbs.Round
	s.OnionKeys = make([]*[32]byte, len(pbs.OnionKeys))
	for i := range s.OnionKeys {
		key := new([32]byte)
		n := copy(key[:], pbs.OnionKeys[i])
		if n != 32 {
			return errors.New("wrong size for key %d: got %d, want %d", i, n, 32)
		}
		s.OnionKeys[i] = key
	}
	s.RawServiceData = pbs.ServiceData
	return nil
}

func (s RoundSettings) Proto() *pb.RoundSettings {
	pbs := &pb.RoundSettings{
		Service:     s.Service,
		Round:       s.Round,
		OnionKeys:   make([][]byte, len(s.OnionKeys)),
		ServiceData: s.RawServiceData,
	}
	for i, key := range s.OnionKeys {
		pbs.OnionKeys[i] = key[:]
	}
	return pbs
}
