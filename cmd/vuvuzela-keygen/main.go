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
	"vuvuzela.io/alpenhorn/errors"
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

	globalConf, err := config.ReadGlobalConfigFile(*serverConfPath)
	if err != nil {
		log.Fatal(err)
	}
	alpConf, err := globalConf.AlpenhornConfig()
	if err != nil {
		log.Fatalf("error reading alpenhorn config from %q: %s", *serverConfPath, err)
	}
	vzConf, err := globalConf.VuvuzelaConfig()
	if err != nil {
		log.Fatalf("error reading vuvuzela config from %q: %s", *serverConfPath, err)
	}
	if err := checkAlpenhornConfig(alpConf); err != nil {
		log.Fatalf("bad server config: %s", err)
	}
	if err := checkVuvuzelaConfig(vzConf); err != nil {
		log.Fatalf("bad server config: %s", err)
	}

	alpConnSettings := alpenhorn.ConnectionSettings{
		EntryAddr: alpConf.Coordinator.ClientAddress,
		PKGAddrs:  make([]string, len(alpConf.PKGs)),
		PKGKeys:   make([]ed25519.PublicKey, len(alpConf.PKGs)),
		Mixers:    make([]ed25519.PublicKey, len(alpConf.Mixers)),
		CDNKey:    alpConf.CDN.Key,
	}
	for i, pkg := range alpConf.PKGs {
		alpConnSettings.PKGAddrs[i] = pkg.ClientAddress
		alpConnSettings.PKGKeys[i] = pkg.Key
	}
	for i, mixer := range alpConf.Mixers {
		alpConnSettings.Mixers[i] = mixer.Key
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

		ConnectionSettings: alpConnSettings,

		ClientPersistPath: clientDest,
	}

	err = client.Persist()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Wrote new Alpenhorn client to %s\n", clientDest)

	for _, pkg := range alpConf.PKGs {
		err := client.Register(*username, pkg.ClientAddress, pkg.Key)
		if err != nil {
			fmt.Printf("! Failed to register with %s: %s\n", pkg.ClientAddress, err)
			continue
		}
		fmt.Printf("Registered with %s\n", pkg.ClientAddress)
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

func checkAlpenhornConfig(alpConf *config.AlpenhornConfig) error {
	if alpConf.Coordinator.ClientAddress == "" {
		return errors.New("no alpenhorn coordinator address")
	}
	if alpConf.CDN.Key == nil {
		return errors.New("no alpenhorn cdn key")
	}
	for i, pkg := range alpConf.PKGs {
		if pkg.Key == nil || pkg.ClientAddress == "" {
			return errors.New("pkg %d is missing key or client address", i+1)
		}
	}
	for i, mixer := range alpConf.Mixers {
		if mixer.Key == nil {
			return errors.New("alpenhorn mixer %d has no key", i+1)
		}
	}
	return nil
}

func checkVuvuzelaConfig(vzConf *config.VuvuzelaConfig) error {
	if vzConf.Coordinator.ClientAddress == "" {
		return errors.New("no vuvuzela coordinator address")
	}
	for i, mixer := range vzConf.Mixers {
		if mixer.Key == nil {
			return errors.New("vuvuzela mixer %d has no key", i+1)
		}
	}
	return nil
}
