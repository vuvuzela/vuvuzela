// Copyright 2018 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package cmdconf

import (
	"bytes"
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"text/template"
	"time"

	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/crypto/rand"
)

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

type MixerConfig struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	ListenAddr string
	DebugAddr  string

	Noise rand.Laplace
}

func NewMixerConfig() *MixerConfig {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &MixerConfig{
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		ListenAddr: "0.0.0.0:2718",
		DebugAddr:  "0.0.0.0:6060",

		Noise: rand.Laplace{
			Mu: 100,
			B:  3.0,
		},
	}

	return conf
}

const mixerTemplate = `# Vuvuzela mixnet server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

listenAddr = {{.ListenAddr | printf "%q"}}
debugAddr = {{.DebugAddr | printf "%q" }}

[noise]
mu = {{.Noise.Mu | printf "%0.1f"}}
b = {{.Noise.B | printf "%0.1f"}}
`

func (c *MixerConfig) TOML() []byte {
	tmpl := template.Must(template.New("mixer").Funcs(funcMap).Parse(mixerTemplate))

	buf := new(bytes.Buffer)
	err := tmpl.Execute(buf, c)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type CoordinatorConfig struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	ListenAddr string

	RoundDelay time.Duration
}

func NewCoordinatorConfig() *CoordinatorConfig {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &CoordinatorConfig{
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		ListenAddr: "0.0.0.0:8000",

		RoundDelay: 800 * time.Millisecond,
	}

	return conf
}

const coordinatorTemplate = `# Vuvuzela coordinator (entry) server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

listenAddr = {{.ListenAddr | printf "%q"}}

roundDelay = {{.RoundDelay | printf "%q"}}
`

func (c *CoordinatorConfig) TOML() []byte {
	tmpl := template.Must(template.New("coordinator").Funcs(funcMap).Parse(coordinatorTemplate))

	buf := new(bytes.Buffer)
	err := tmpl.Execute(buf, c)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}
