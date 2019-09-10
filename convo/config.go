// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package convo

import (
	"crypto/ed25519"
	"encoding/json"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/vuvuzela/mixnet"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson .

func init() {
	config.RegisterService("Convo", &ConvoConfig{})
}

const ConvoConfigVersion = 1

type ConvoConfig struct {
	Version     int
	Coordinator CoordinatorConfig
	MixServers  []mixnet.PublicServerConfig
}

func (c *ConvoConfig) UseLatestVersion() {
	c.Version = ConvoConfigVersion
}

//easyjson:readable
type CoordinatorConfig struct {
	Key     ed25519.PublicKey
	Address string
}

//easyjson:readable
type convoV1 struct {
	Version     int
	Coordinator keyAddr
	MixServers  []keyAddr
}

//easyjson:readable
type keyAddr struct {
	Key     ed25519.PublicKey
	Address string
}

func (c *ConvoConfig) v1() (*convoV1, error) {
	c1 := &convoV1{
		Version:     1,
		Coordinator: keyAddr{c.Coordinator.Key, c.Coordinator.Address},
		MixServers:  make([]keyAddr, len(c.MixServers)),
	}
	for i, srv := range c.MixServers {
		c1.MixServers[i] = keyAddr{srv.Key, srv.Address}
	}
	return c1, nil
}

func (c *ConvoConfig) fromV1(c1 *convoV1) error {
	c.Version = 1
	c.Coordinator = CoordinatorConfig{c1.Coordinator.Key, c1.Coordinator.Address}
	c.MixServers = make([]mixnet.PublicServerConfig, len(c1.MixServers))
	for i, srv := range c1.MixServers {
		c.MixServers[i] = mixnet.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	return nil
}

func (c *ConvoConfig) MarshalJSON() ([]byte, error) {
	switch c.Version {
	case 1:
		c1, err := c.v1()
		if err != nil {
			return nil, err
		}
		return json.Marshal(c1)
	default:
		return nil, errors.New("unknown ConvoConfig version: %d", c.Version)
	}
}

func (c *ConvoConfig) UnmarshalJSON(data []byte) error {
	version, err := getVersionFromJSON(data)
	if err != nil {
		return err
	}
	switch version {
	case 1:
		c1 := new(convoV1)
		err := json.Unmarshal(data, c1)
		if err != nil {
			return err
		}
		return c.fromV1(c1)
	default:
		return errors.New("unknown ConvoConfig version: %d", c.Version)
	}
}

func (c *ConvoConfig) Validate() error {
	if len(c.Coordinator.Key) != ed25519.PublicKeySize {
		return errors.New("invalid coordinator key: %#v", c.Coordinator.Key)
	}
	if c.Coordinator.Address == "" {
		return errors.New("empty coordinator address")
	}

	if len(c.MixServers) == 0 {
		return errors.New("no mix servers defined for convo protocol")
	}

	for i, mix := range c.MixServers {
		if len(mix.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for mixer %d: %s", i, mix.Key)
		}
		if mix.Address == "" {
			return errors.New("empty address for mix server %d", i)
		}
	}

	return nil
}

func getVersionFromJSON(data []byte) (int, error) {
	type ver struct {
		Version int
	}
	v := new(ver)
	err := json.Unmarshal(data, v)
	if err != nil {
		return -1, err
	}
	return v.Version, nil
}
