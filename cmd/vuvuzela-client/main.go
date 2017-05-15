package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/config"
)

var username = flag.String("username", "", "Alpenhorn username")
var serverConfPath = flag.String("servers", "", "path to server config")

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

	// Reading the global config is a temporary kludge until we save
	// Vuvuzela's connection settings in user state.
	globalConf, err := config.ReadGlobalConfigFile(*serverConfPath)
	if err != nil {
		log.Fatal(err)
	}
	vzConf, err := globalConf.VuvuzelaConfig()
	if err != nil {
		log.Fatalf("error reading vuvuzela config from %q: %s", *serverConfPath, err)
	}
	mixers := make([]ed25519.PublicKey, len(vzConf.Mixers))
	for i, mixer := range vzConf.Mixers {
		mixers[i] = mixer.Key
	}

	vzClient := &Client{
		EntryServer: vzConf.Coordinator.ClientAddress,
		Mixers:      mixers,
	}

	gc := &GuiClient{
		myName:          alpenhornClient.Username,
		convoClient:     vzClient,
		alpenhornClient: alpenhornClient,
	}
	alpenhornClient.Handler = gc

	gc.Run()
}
