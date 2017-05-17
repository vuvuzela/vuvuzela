// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"text/template"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/vuvuzela/mixnet"
)

var (
	globalConfPath = flag.String("global", "", "global config file")
	confPath       = flag.String("conf", "", "config file")
	doinit         = flag.Bool("init", false, "create config file")
)

type Config struct {
	ListenAddr string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	Noise rand.Laplace
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Vuvuzela mixnet server config

listenAddr = {{.ListenAddr | printf "%q"}}

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

[noise]
mu = {{.Noise.Mu | printf "%0.1f"}}
b = {{.Noise.B | printf "%0.1f"}}
`

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		ListenAddr: "0.0.0.0:2718",
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		Noise: rand.Laplace{
			Mu: 100,
			B:  3.0,
		},
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}
	data := buf.Bytes()

	path := "vuvuzela-mixer-init.conf"
	err = ioutil.WriteFile(path, data, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", path)
}

func init() {
	//log.SetFormatter(&log.JSONFormatter{})
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
	coordinatorKey := vzConf.Coordinator.Key
	if coordinatorKey == nil {
		log.Fatal("no vuvuzela coordinator key specified in global config")
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

	mixers := vzConf.Mixers
	ourPos := -1
	for i, mixer := range mixers {
		if bytes.Equal(mixer.Key, conf.PublicKey) {
			ourPos = i
			break
		}
	}
	if ourPos < 0 {
		log.Fatal("our key was not found in the vuvuzela mixer list")
	}

	var prevServerKey ed25519.PublicKey
	if ourPos == 0 {
		prevServerKey = coordinatorKey
	} else {
		prevServerKey = mixers[ourPos-1].Key
		if prevServerKey == nil {
			// first mixer in the config file is called "mixer 1"
			log.Fatalf("vuvuzela mixer %d has no key", ourPos-1+1)
		}
	}

	var nextServer *vrpc.Client
	lastServer := ourPos == len(mixers)-1
	if !lastServer {
		next := mixers[ourPos+1]
		if next.Key == nil || next.Address == "" {
			log.Fatalf("vuvuzela mixer %d is missing a key or address", ourPos+1+1)
		}
		nextServer, err = vrpc.Dial("tcp", next.Address, next.Key, conf.PrivateKey, runtime.NumCPU())
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
	}

	server := &mixnet.Server{
		SigningKey:     conf.PrivateKey,
		ServerPosition: ourPos,
		NumServers:     len(mixers),
		NextServer:     nextServer,

		Laplace: conf.Noise,

		AccessCounts: make(chan mixnet.AccessCount, 64),
	}

	if lastServer {
		histogram := &Histogram{Mu: conf.Noise.Mu, NumServers: len(mixers)}
		go histogram.run(server.AccessCounts)
	}

	srv := new(vrpc.Server)
	if err := srv.Register(coordinatorKey, "Coordinator", &mixnet.CoordinatorService{server}); err != nil {
		log.Fatalf("vrpc.Register: %s", err)
	}

	if err := srv.Register(prevServerKey, "Chain", &mixnet.ChainService{server}); err != nil {
		log.Fatalf("vrpc.Register: %s", err)
	}

	err = srv.ListenAndServe(conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
