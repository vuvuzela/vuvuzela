package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"io/ioutil"

	log "github.com/Sirupsen/logrus"

	. "vuvuzela.io/vuvuzela"
	. "vuvuzela.io/vuvuzela/internal"
)

var doInit = flag.Bool("init", false, "create default config file")
var confPath = flag.String("conf", "confs/client.conf", "config file")
var pkiPath = flag.String("pki", "confs/pki.conf", "pki file")

type Conf struct {
	MyName       string
	MyPublicKey  *BoxKey
	MyPrivateKey *BoxKey
}

func WriteDefaultConf(path string) {
	myPublicKey, myPrivateKey, err := GenerateBoxKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateBoxKey: %s", err)
	}
	conf := &Conf{
		MyPublicKey:  myPublicKey,
		MyPrivateKey: myPrivateKey,
	}

	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		log.Fatalf("json encoding error: %s", err)
	}
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		log.Fatalf("WriteFile: %s", err)
	}
}

func main() {
	flag.Parse()

	if *doInit {
		WriteDefaultConf(*confPath)
		return
	}

	pki := ReadPKI(*pkiPath)

	conf := new(Conf)
	ReadJSONFile(*confPath, conf)
	if conf.MyName == "" || conf.MyPublicKey == nil || conf.MyPrivateKey == nil {
		log.Fatalf("missing required fields: %s", *confPath)
	}

	gc := &GuiClient{
		pki:          pki,
		myName:       conf.MyName,
		myPublicKey:  conf.MyPublicKey,
		myPrivateKey: conf.MyPrivateKey,
	}
	gc.Run()
}
