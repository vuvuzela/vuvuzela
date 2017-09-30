// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package vuvuzela

import (
	"encoding/json"
	"io/ioutil"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/internal/ioutil2"
	"vuvuzela.io/vuvuzela/convo"
)

type persistedState struct {
	ConvoConfig *config.SignedConfig
}

func (c *Client) persistLocked() error {
	st := &persistedState{
		ConvoConfig: c.convoConfig,
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}

	return ioutil2.WriteFileAtomic(c.PersistPath, data, 0600)
}

// LoadClient loads a client from persisted state at the given path.
// You should set the client's KeywheelPersistPath before connecting.
func LoadClient(clientPersistPath string) (*Client, error) {
	clientData, err := ioutil.ReadFile(clientPersistPath)
	if err != nil {
		return nil, err
	}

	st := new(persistedState)
	err = json.Unmarshal(clientData, st)
	if err != nil {
		return nil, err
	}

	c := &Client{
		PersistPath: clientPersistPath,
	}
	c.loadStateLocked(st)
	return c, nil
}

func (c *Client) loadStateLocked(st *persistedState) {
	c.convoConfig = st.ConvoConfig
	c.convoConfigHash = st.ConvoConfig.Hash()
}

// Persist writes the client's state to disk. The client persists
// itself automatically, so Persist is only needed when creating
// a new client.
func (c *Client) Persist() error {
	c.mu.Lock()
	err := c.persistLocked()
	c.mu.Unlock()
	return err
}

func (c *Client) Bootstrap(startingConvoConfig *config.SignedConfig) error {
	if err := startingConvoConfig.Validate(); err != nil {
		return err
	}

	_, ok := startingConvoConfig.Inner.(*convo.ConvoConfig)
	if !ok {
		return errors.New("unexpected inner config type: %T", startingConvoConfig.Inner)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.convoConfig = startingConvoConfig
	c.convoConfigHash = startingConvoConfig.Hash()

	return nil
}
