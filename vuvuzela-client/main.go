package main

import (
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
	MyName string
}

func WriteDefaultConf(path string) {
	conf := &Conf{}
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
	if conf.MyName == "" {
		log.Fatalf("missing required fields: %s", *confPath)
	}

	gc := &GuiClient{
		pki:    pki,
		myName: conf.MyName,
	}
	gc.Run()
}
