package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/rpc"
	"runtime"
	"sync"

	log "github.com/Sirupsen/logrus"

	vrand "vuvuzela.io/crypto/rand"
	. "vuvuzela.io/vuvuzela"
	. "vuvuzela.io/vuvuzela/internal"
	"vuvuzela.io/vuvuzela/vrpc"
)

var doInit = flag.Bool("init", false, "create default config file")
var confPath = flag.String("conf", "", "config file")
var pkiPath = flag.String("pki", "confs/pki.conf", "pki file")
var muOverride = flag.Float64("mu", -1.0, "override ConvoMu in conf file")

type Conf struct {
	ServerName string
	PublicKey  *BoxKey
	PrivateKey *BoxKey
	ListenAddr string `json:",omitempty"`
	DebugAddr  string `json:",omitempty"`

	ConvoMu float64
	ConvoB  float64

	DialMu float64
	DialB  float64
}

func WriteDefaultConf(path string) {
	myPublicKey, myPrivateKey, err := GenerateBoxKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %s", err)
	}
	conf := &Conf{
		ServerName: "mit",
		PublicKey:  myPublicKey,
		PrivateKey: myPrivateKey,
	}

	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		log.Fatalf("json encoding error: %s", err)
	}
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		log.Fatalf("WriteFile: %s", err)
	}
	fmt.Printf("wrote %q\n", path)
}

func main() {
	flag.Parse()
	log.SetFormatter(&ServerFormatter{})

	if *confPath == "" {
		log.Fatalf("must specify -conf flag")
	}

	if *doInit {
		WriteDefaultConf(*confPath)
		return
	}

	pki := ReadPKI(*pkiPath)

	conf := new(Conf)
	ReadJSONFile(*confPath, conf)
	if conf.ServerName == "" || conf.PublicKey == nil || conf.PrivateKey == nil {
		log.Fatalf("missing required fields: %s", *confPath)
	}

	if *muOverride >= 0 {
		conf.ConvoMu = *muOverride
	}

	var err error
	var client *vrpc.Client
	if addr := pki.NextServer(conf.ServerName); addr != "" {
		client, err = vrpc.Dial("tcp", addr, runtime.NumCPU())
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
	}

	var idle sync.Mutex

	convoService := &ConvoService{
		Idle: &idle,

		Laplace: vrand.Laplace{
			Mu: conf.ConvoMu,
			B:  conf.ConvoB,
		},

		PKI:        pki,
		ServerName: conf.ServerName,
		PrivateKey: conf.PrivateKey,

		Client:     client,
		LastServer: client == nil,
	}
	InitConvoService(convoService)

	if convoService.LastServer {
		histogram := &Histogram{Mu: conf.ConvoMu, NumServers: len(pki.ServerOrder)}
		go histogram.run(convoService.AccessCounts)
	}

	dialService := &DialService{
		Idle: &idle,

		Laplace: vrand.Laplace{
			Mu: conf.ConvoMu,
			B:  conf.ConvoB,
		},

		PKI:        pki,
		ServerName: conf.ServerName,
		PrivateKey: conf.PrivateKey,

		Client:     client,
		LastServer: client == nil,
	}
	InitDialService(dialService)

	if err := rpc.Register(dialService); err != nil {
		log.Fatalf("rpc.Register: %s", err)
	}
	if err := rpc.Register(convoService); err != nil {
		log.Fatalf("rpc.Register: %s", err)
	}

	if conf.DebugAddr != "" {
		go func() {
			log.Println(http.ListenAndServe(conf.DebugAddr, nil))
		}()
		runtime.SetBlockProfileRate(1)
	}

	if conf.ListenAddr == "" {
		conf.ListenAddr = DefaultServerAddr
	}
	listen, err := net.Listen("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatal("Listen:", err)
	}
	rpc.Accept(listen)
}
