// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"flag"
	"fmt"
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

var (
	username = flag.String("username", "", "Alpenhorn username (e.g., your email address)")
)

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

	addFriendConfig, err := config.StdClient.CurrentConfig("AddFriend")
	if err != nil {
		log.Fatalf("error fetching latest addfriend config: %s", err)
	}
	dialingConfig, err := config.StdClient.CurrentConfig("Dialing")
	if err != nil {
		log.Fatalf("error fetching latest dialing config: %s", err)
	}

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

		ClientPersistPath: clientDest,
	}
	err = client.Bootstrap(
		addFriendConfig,
		dialingConfig,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Persist()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Bootstrapped new Alpenhorn client using latest configs.\n")
	fmt.Printf("! Cautious users should verify the initial configs in: %s\n", clientDest)

	pkgServers := addFriendConfig.Inner.(*config.AddFriendConfig).PKGServers
	for _, pkg := range pkgServers {
		err := client.Register(*username, pkg.Address, pkg.Key)
		if err != nil {
			fmt.Printf("! Failed to register with %s: %s\n", pkg.Address, err)
			continue
		}
		fmt.Printf("Registered with %s\n", pkg.Address)
	}

	vzClientDest := filepath.Join(confHome, *username+"-vuvuzela-client-state")
	checkOverwrite(vzClientDest)

	convoConfig, err := config.StdClient.CurrentConfig("Convo")
	if err != nil {
		log.Fatalf("error fetching latest convo config: %s", err)
	}

	vzClient := &vuvuzela.Client{
		PersistPath: vzClientDest,
	}
	err = vzClient.Bootstrap(convoConfig)
	if err != nil {
		log.Fatal(err)
	}
	err = vzClient.Persist()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bootstrapped new Vuvuzela client using latest configs.\n")
	fmt.Printf("! Cautious users should verify the initial configs in: %s\n", vzClientDest)

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
