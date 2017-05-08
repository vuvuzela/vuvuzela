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
)

var (
	username       = flag.String("username", "", "Alpenhorn username (e.g., your email address)")
	serverConfPath = flag.String("servers", "", "path to server config")
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
	if *serverConfPath == "" {
		fmt.Println("no servers specified")
		os.Exit(1)
	}

	alpConfig, err := config.ReadFile(*serverConfPath)
	if err != nil {
		log.Fatal(err)
	}

	var connectionSettings alpenhorn.ConnectionSettings
	connectionSettings.Bootstrap(alpConfig.AlpenhornSettings, alpConfig.ServerMap)

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

	clientStateBasename := *username + ".state"
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

		ConnectionSettings: connectionSettings,

		ClientPersistPath: clientDest,
	}

	err = client.Persist()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Wrote new Alpenhorn client to %s\n", clientDest)

	pkgs := alpConfig.GetServers(alpConfig.PKGServers)
	for _, pkg := range pkgs {
		err := client.Register(*username, pkg.Address, pkg.PublicKey)
		if err != nil {
			fmt.Printf("! Failed to register with %s: %s\n", pkg.Address, err)
			continue
		}
		fmt.Printf("Registered with %s\n", pkg.Address)
	}

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
