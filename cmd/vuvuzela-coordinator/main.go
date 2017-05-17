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
	"path/filepath"
	"runtime"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/vuvuzela/coordinator"
)

var (
	globalConfPath = flag.String("global", "", "global config file")
	confPath       = flag.String("conf", "", "config file")
	doinit         = flag.Bool("init", false, "create config file")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	ListenAddr string
	PersistDir string

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
persistDir = {{.PersistDir | printf "%q" }}

roundDelay = {{.RoundDelay | printf "%q"}}

# mixWait is how long to wait after announcing the mixnet round
# settings and before closing the round.
mixWait = {{.MixWait | printf "%q"}}
`

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		ListenAddr: "0.0.0.0:8000",
		PersistDir: "/var/run/vuvuzela",

		RoundDelay: 5 * time.Second,
		MixWait:    2 * time.Second,
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}
	data := buf.Bytes()

	path := "coordinator-init.conf"
	err = ioutil.WriteFile(path, data, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", path)
}

func main() {
	flag.Parse()

	if *doinit {
		writeNewConfig()
		return
	}

	if *globalConfPath == "" {
		fmt.Println("specify global config file with -global")
		os.Exit(1)
	}

	if *confPath == "" {
		fmt.Println("specify config file with -conf")
		os.Exit(1)
	}

	globalConf, err := config.ReadGlobalConfigFile(*globalConfPath)
	if err != nil {
		log.Fatal(err)
	}
	vzConf, err := globalConf.VuvuzelaConfig()
	if err != nil {
		log.Fatalf("error reading vuvuzela config from %q: %s", *globalConfPath, err)
	}
	if len(vzConf.Mixers) == 0 {
		log.Fatalf("no mix servers defined in global conf: %s", *globalConfPath)
	}

	data, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %q: %s", *confPath, err)
	}

	mixConns := make([]*vrpc.Client, len(vzConf.Mixers))
	for i, mixer := range vzConf.Mixers {
		if mixer.Key == nil || mixer.Address == "" {
			log.Fatalf("mixer %d is missing a key or address", i+1)
		}
		numConns := 1
		if i == 0 {
			numConns = runtime.NumCPU()
		}

		log.Printf("connecting to mixer: %s", mixer.Address)
		client, err := vrpc.Dial("tcp", mixer.Address, mixer.Key, conf.PrivateKey, numConns)
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
		mixConns[i] = client
	}

	server := &coordinator.Server{
		PersistPath: filepath.Join(conf.PersistDir, "vuvuzela-coordinator-state"),

		MixServers: mixConns,
		MixWait:    conf.MixWait,

		RoundWait: conf.RoundDelay,
	}
	err = server.Run()
	if err != nil {
		log.Fatalf("error starting convo loop: %s", err)
	}
	http.Handle("/ws", server)

	log.Printf("listening on: %s", conf.ListenAddr)
	err = http.ListenAndServe(conf.ListenAddr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
