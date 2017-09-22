// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package convo

import (
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/vuvuzela/mixnet"
)

func init() {
	config.RegisterService("Convo", &ConvoConfig{})
}

type ConvoConfig struct {
	MixServers []mixnet.PublicServerConfig
}

func (c *ConvoConfig) Validate() error {
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
