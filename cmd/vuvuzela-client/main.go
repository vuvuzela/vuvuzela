package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/vuvuzela"
)

var username = flag.String("username", "", "Alpenhorn username")

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

	alpStatePath := filepath.Join(confHome, fmt.Sprintf("%s-alpenhorn-client-state", *username))
	alpenhornClient, err := alpenhorn.LoadClient(alpStatePath)
	if os.IsNotExist(err) {
		fmt.Printf("No Alpenhorn client state found for username %s in %s.\n", *username, confHome)
		fmt.Printf("Use vuvuzela-keygen to generate new client state.\n")
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("Failed to load alpenhorn client: %s", err)
		return
	}

	keywheelPath := filepath.Join(confHome, fmt.Sprintf("%s-keywheel", *username))
	alpenhornClient.KeywheelPersistPath = keywheelPath
	alpenhornClient.ConfigClient = config.StdClient

	vzStatePath := filepath.Join(confHome, fmt.Sprintf("%s-vuvuzela-client-state", *username))
	vzClient, err := vuvuzela.LoadClient(vzStatePath)
	if os.IsNotExist(err) {
		fmt.Printf("No Vuvuzela client state found for username %s in %s.\n", *username, confHome)
		fmt.Printf("Use vuvuzela-keygen to generate new client state.\n")
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("Failed to load vuvuzela client: %s", err)
		return
	}
	vzClient.ConfigClient = config.StdClient

	gc := &GuiClient{
		myName:          alpenhornClient.Username,
		convoClient:     vzClient,
		alpenhornClient: alpenhornClient,
	}
	alpenhornClient.Handler = gc

	gc.Run()
}
