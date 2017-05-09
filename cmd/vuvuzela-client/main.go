package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	log "github.com/Sirupsen/logrus"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/vuvuzela"
)

var username = flag.String("username", "", "Alpenhorn username")
var pkiPath = flag.String("pki", "confs/pki.conf", "pki file")

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
	if err := os.MkdirAll(confHome, 0700); err != nil {
		log.Fatal(err)
	}

	alpStatePath := filepath.Join(confHome, fmt.Sprintf("%s.state", *username))
	alpenhornClient, err := alpenhorn.LoadClient(alpStatePath)
	if os.IsNotExist(err) {
		fmt.Printf("No client state found for username %s in %s.\n", *username, confHome)
		fmt.Printf("Use vuvuzela-keygen to generate new client state.\n")
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("Failed to load alpenhorn client: %s", err)
		return
	}

	keywheelPath := filepath.Join(confHome, fmt.Sprintf("%s.keywheel", *username))
	alpenhornClient.KeywheelPersistPath = keywheelPath

	pki := vuvuzela.ReadPKI(*pkiPath)

	gc := &GuiClient{
		pki:             pki,
		myName:          alpenhornClient.Username,
		convoClient:     NewClient(pki.EntryServer),
		alpenhornClient: alpenhornClient,
	}
	alpenhornClient.Handler = gc

	gc.Run()
}
