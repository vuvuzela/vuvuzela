// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/vuvuzela/coordinator"
)

var (
	doInit = flag.Bool("init", false, "initialize a coordinator for the first time")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	ListenAddr string

	RoundDelay time.Duration
	MixWait    time.Duration
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Vuvuzela coordinator (entry) server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}
listenAddr = {{.ListenAddr | printf "%q"}}

roundDelay = {{.RoundDelay | printf "%q"}}

# mixWait is how long to wait after announcing the mixnet round
# settings and before closing the round.
mixWait = {{.MixWait | printf "%q"}}
`

func initService(service string, confHome string) {
	fmt.Printf("--> Initializing %q service.\n", service)
	coordinatorPersistPath := filepath.Join(confHome, strings.ToLower(service)+"-coordinator-state")

	doCoordinator := overwrite(coordinatorPersistPath)

	if !doCoordinator {
		fmt.Println("Nothing to do.")
		return
	}

	server := &coordinator.Server{
		Service:     service,
		PersistPath: coordinatorPersistPath,
	}
	err := server.Persist()
	if err != nil {
		log.Fatalf("failed to create coordinator server state for service %q: %s", service, err)
	}

	fmt.Printf("! Wrote coordinator server state: %s\n", coordinatorPersistPath)
}

func initCoordinator() {
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

	initService("Convo", confHome)

	fmt.Printf("--> Generating coordinator key pair and config.\n")
	confPath := filepath.Join(confHome, "coordinator.conf")
	if overwrite(confPath) {
		writeNewConfig(confPath)
		fmt.Printf("--> Please edit the config file before running the server.\n")
	}
}

func writeNewConfig(path string) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		ListenAddr: "0.0.0.0:8000",

		RoundDelay: 5 * time.Second,
		MixWait:    2 * time.Second,
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}

	err = ioutil.WriteFile(path, buf.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("! Wrote new config file: %s\n", path)
}

func main() {
	flag.Parse()

	if *doInit {
		initCoordinator()
		return
	}

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	confHome := filepath.Join(u.HomeDir, ".vuvuzela")

	confPath := filepath.Join(confHome, "coordinator.conf")
	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %s: %s", confPath, err)
	}

	coordinatorPresistPath := filepath.Join(confHome, "convo-coordinator-state")
	convoServer := &coordinator.Server{
		Service:    "Convo",
		PrivateKey: conf.PrivateKey,

		ConfigClient: config.StdClient,

		MixWait:   conf.MixWait,
		RoundWait: conf.RoundDelay,

		PersistPath: coordinatorPresistPath,
	}
	err = convoServer.LoadPersistedState()
	if err != nil {
		log.Fatalf("error loading persisted state: %s", err)
	}

	err = convoServer.Run()
	if err != nil {
		log.Fatalf("error starting convo loop: %s", err)
	}

	http.Handle("/convo/", http.StripPrefix("/convo", convoServer))

	listener, err := edtls.Listen("tcp", conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls listen: %s", err)
	}

	log.Infof("Listening on: %s", conf.ListenAddr)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func overwrite(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true
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
		return false
	}
	if yesno[0] != 'y' && yesno[0] != 'Y' {
		return false
	}
	return true
}
