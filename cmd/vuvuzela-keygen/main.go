// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/vuvuzela"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson .

var (
	username          = flag.String("username", "", "Alpenhorn username (e.g., your email address)")
	bootstrapConfPath = flag.String("bootstrap", "", "path to bootstrap config")
)

type BootstrapConfig struct {
	Alpenhorn *CoordinatorInfo
	Vuvuzela  *CoordinatorInfo

	SignedConfigs SignedConfigs
}

type SignedConfigs struct {
	AddFriend *config.SignedConfig
	Dialing   *config.SignedConfig
	Convo     *config.SignedConfig
}

//easyjson:readable
type CoordinatorInfo struct {
	CoordinatorKey     ed25519.PublicKey
	CoordinatorAddress string
}

func init() {
	log.SetFlags(0)
	log.SetPrefix("vuvuzela-keygen: ")
}

func main() {
	flag.Parse()

	if *username == "" {
		fmt.Println("no username specified")
		os.Exit(1)
	}
	if *bootstrapConfPath == "" {
		fmt.Println("no bootstrap config specified")
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(*bootstrapConfPath)
	if err != nil {
		log.Fatal(err)
	}
	bootstrapConfig := new(BootstrapConfig)
	err = json.Unmarshal(data, bootstrapConfig)
	if err != nil {
		log.Fatalf("error parsing config: %s", err)
	}
	bootstrapConfig.Validate()

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	confHome := filepath.Join(u.HomeDir, ".vuvuzela")
	err = os.Mkdir(confHome, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", confHome)
	} else if !os.IsExist(err) {
		log.Fatal(err)
	}

	clientStateBasename := *username + "-alpenhorn-client-state"
	clientDest := filepath.Join(confHome, clientStateBasename)
	checkOverwrite(clientDest)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	client := alpenhorn.Client{
		Username:           *username,
		LongTermPrivateKey: privateKey,
		LongTermPublicKey:  publicKey,

		// For now, reuse the long term key for the PKG login key.
		PKGLoginKey: privateKey,

		CoordinatorAddress: bootstrapConfig.Alpenhorn.CoordinatorAddress,
		CoordinatorKey:     bootstrapConfig.Alpenhorn.CoordinatorKey,

		ClientPersistPath: clientDest,
	}
	err = client.Bootstrap(
		bootstrapConfig.SignedConfigs.AddFriend,
		bootstrapConfig.SignedConfigs.Dialing,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Persist()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Wrote new Alpenhorn client to %s\n", clientDest)

	addFriendConfig := bootstrapConfig.SignedConfigs.AddFriend.Inner.(*config.AddFriendConfig)
	for _, pkg := range addFriendConfig.PKGServers {
		err := client.Register(*username, pkg.Address, pkg.Key)
		if err != nil {
			fmt.Printf("! Failed to register with %s: %s\n", pkg.Address, err)
			continue
		}
		fmt.Printf("Registered with %s\n", pkg.Address)
	}

	vzClientDest := filepath.Join(confHome, *username+"-vuvuzela-client-state")
	checkOverwrite(vzClientDest)

	vzClient := &vuvuzela.Client{
		CoordinatorAddress: bootstrapConfig.Vuvuzela.CoordinatorAddress,
		CoordinatorKey:     bootstrapConfig.Vuvuzela.CoordinatorKey,
		PersistPath:        vzClientDest,
	}
	err = vzClient.Bootstrap(bootstrapConfig.SignedConfigs.Convo)
	if err != nil {
		log.Fatal(err)
	}
	err = vzClient.Persist()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Wrote new Vuvuzela client to %s\n", vzClientDest)

	fmt.Printf("* Username: %s\n", *username)
	keyString := base32.EncodeToString(publicKey)
	fmt.Printf("* PublicKey: %s\n", keyString)
}

func checkOverwrite(path string) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s already exists.\n", path)
	fmt.Printf("Overwrite (y/N)? ")
	var yesno [3]byte
	n, err := os.Stdin.Read(yesno[:])
	if err != nil {
		log.Fatal(err)
	}
	if n == 0 {
		os.Exit(1)
	}
	if yesno[0] != 'y' && yesno[0] != 'Y' {
		os.Exit(1)
	}
}

func (c *BootstrapConfig) Validate() {
	if c.Alpenhorn == nil {
		log.Fatalf("missing alpenhorn coordinator info in bootstrap config")
	}
	if len(c.Alpenhorn.CoordinatorKey) != ed25519.PublicKeySize {
		log.Fatalf("invalid alpenhorn coordinator key: got %d bytes, want %d", len(c.Alpenhorn.CoordinatorKey), ed25519.PublicKeySize)
	}

	if c.Vuvuzela == nil {
		log.Fatalf("missing vuvuzela coordinator info in bootstrap config")
	}
	if len(c.Vuvuzela.CoordinatorKey) != ed25519.PublicKeySize {
		log.Fatalf("invalid vuvuzela coordinator key: got %d bytes, want %d", len(c.Vuvuzela.CoordinatorKey), ed25519.PublicKeySize)
	}

	if c.SignedConfigs.AddFriend == nil {
		log.Fatal("missing addfriend signed config in bootstrap config")
	}
	if c.SignedConfigs.Dialing == nil {
		log.Fatal("missing dialing signed config in bootstrap config")
	}
	if c.SignedConfigs.Convo == nil {
		log.Fatal("missing convo signed config in bootstrap config")
	}

	if err := c.SignedConfigs.AddFriend.Validate(); err != nil {
		log.Fatalf("invalid addfriend config: %s", err)
	}
	if err := c.SignedConfigs.Dialing.Validate(); err != nil {
		log.Fatalf("invalid dialing config: %s", err)
	}
	if err := c.SignedConfigs.Convo.Validate(); err != nil {
		log.Fatalf("invalid convo config: %s", err)
	}
}
