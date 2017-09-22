// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package coordinator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/internal/ioutil2"
)

// version is the current version number of the persisted state format.
const version byte = 1

type persistedState struct {
	Round uint32
}

func (srv *Server) LoadPersistedState() error {
	configServer, err := config.LoadServer(srv.ConfigServerPersistPath)
	if err != nil {
		return err
	}
	srv.configServer = configServer

	data, err := ioutil.ReadFile(srv.PersistPath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("no data: %s", srv.PersistPath)
	}

	ver := data[0]
	if ver != version {
		return fmt.Errorf("unexpected version: want version %d, got %d", version, ver)
	}

	var st persistedState
	err = json.Unmarshal(data[1:], &st)
	if err != nil {
		return err
	}

	srv.mu.Lock()
	srv.round = st.Round
	srv.mu.Unlock()

	return nil
}

func (srv *Server) Persist() error {
	srv.mu.Lock()
	err := srv.persistLocked()
	srv.mu.Unlock()
	return err
}

func (srv *Server) persistLocked() error {
	st := &persistedState{
		Round: srv.round,
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(version)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ") // for easier debugging
	err := enc.Encode(st)
	if err != nil {
		return err
	}

	return ioutil2.WriteFileAtomic(srv.PersistPath, buf.Bytes(), 0600)
}
