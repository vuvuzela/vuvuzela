// Copyright 2018 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"time"

	"vuvuzela.io/alpenhorn/pkg"
)

func (gc *GuiClient) Connect() {
	if gc.CheckPKGStatus() {
		gc.EnsureConnected()
	}
}

func (gc *GuiClient) EnsureConnected() {
	gc.connectOnce.Do(func() {
		go gc.connectLoop("Convo", gc.convoClient.ConnectConvo)
		go gc.connectLoop("AddFriend", gc.alpenhornClient.ConnectAddFriend)
		go gc.connectLoop("Dialing", gc.alpenhornClient.ConnectDialing)
	})
}

const connectRetry = 10 * time.Second

func (gc *GuiClient) connectLoop(service string, connectFunc func() (chan error, error)) {
	var prevErr error
	for {
		disconnect, err := connectFunc()
		if err != nil {
			if prevErr == nil || (err.Error() != prevErr.Error()) {
				// Don't repeat the same error message over and over again.
				gc.WarnfSync("Error connecting to %s service: %s (retrying every %s)\n", service, err, connectRetry)
				prevErr = err
			}
			time.Sleep(connectRetry)
			continue
		}
		gc.WarnfSync("Connected to %s service!\n", service)
		prevErr = nil
		err = <-disconnect
		gc.WarnfSync("Disconnected from %s service: %s (reconnecting in %s)\n", service, err, connectRetry)
		time.Sleep(connectRetry)
	}
}

func (gc *GuiClient) CheckPKGStatus() bool {
	pkgStats := gc.alpenhornClient.PKGStatus()
	var numOK, numUnregistered int
	for _, st := range pkgStats {
		if st.Error == nil {
			numOK++
			continue
		}
		switch err := st.Error.(type) {
		case pkg.Error:
			if err.Code == pkg.ErrNotRegistered {
				numUnregistered++
				continue
			}
		}
	}

	if numUnregistered == len(pkgStats) {
		gc.WarnfSync("Username %q not registered. Visit https://vuvuzela.io to get started.\n", gc.alpenhornClient.Username)
		return false
	} else if numOK != len(pkgStats) {
		buf := new(bytes.Buffer)
		for _, st := range pkgStats {
			fmt.Fprintf(buf, " ·  PKG %s: %s\n", st.Server.Address, statusString(st.Error))
		}
		gc.WarnfSync("Connection error: inconsistent PKG status for %q:\n%s", gc.alpenhornClient.Username, buf.String())
		gc.WarnfSync("Type /connect after resolving the issue to try again.\n")
		return false
	}

	return true
}

func (gc *GuiClient) RegisterAll(token string) {
	pkgStats := gc.alpenhornClient.PKGStatus()
	buf := new(bytes.Buffer)
	numOK := 0
	for _, st := range pkgStats {
		fmt.Fprintf(buf, " ·  ")
		if st.Error == nil {
			fmt.Fprintf(buf, "PKG %s: OK (already registered)\n", st.Server.Address)
			numOK++
			continue
		}
		pkgErr, ok := st.Error.(pkg.Error)
		if !ok {
			fmt.Fprintf(buf, "PKG %s: %s\n", st.Server.Address, st.Error)
			continue
		}
		if pkgErr.Code != pkg.ErrNotRegistered {
			fmt.Fprintf(buf, "PKG %s: %s\n", st.Server.Address, pkgErr)
			continue
		}
		err := gc.alpenhornClient.Register(st.Server, token)
		if err != nil {
			fmt.Fprintf(buf, "PKG %s: failed to register: %s\n", st.Server.Address, err)
			continue
		}
		fmt.Fprintf(buf, "PKG %s: OK (registered)\n", st.Server.Address)
		numOK++
	}
	gc.WarnfSync("Registration status for %q:\n%s", gc.alpenhornClient.Username, buf.String())
	if numOK == len(pkgStats) {
		// Don't require the user to type /connect after successful registration.
		gc.EnsureConnected()
	}
}

func statusString(err error) string {
	if err == nil {
		return "OK"
	}
	switch err := err.(type) {
	case pkg.Error:
		switch err.Code {
		case pkg.ErrNotRegistered:
			return "Username not registered"
		case pkg.ErrInvalidSignature:
			return "Invalid signature (username taken)"
		}
	}
	return err.Error()
}
