// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"vuvuzela.io/alpenhorn/cmd/cmdutil"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/vuvuzela/cmd/cmdconf"
	"vuvuzela.io/vuvuzela/coordinator"
	"vuvuzela.io/vuvuzela/internal/vzlog"
)

var (
	doInit      = flag.Bool("init", false, "initialize a coordinator for the first time")
	persistPath = flag.String("persist", "persist", "persistent data directory")
)

func initService(service string) {
	fmt.Printf("--> Initializing %q service.\n", service)
	servicePersistPath := filepath.Join(*persistPath, strings.ToLower(service)+"-coordinator-state")

	doCoordinator := cmdutil.Overwrite(servicePersistPath)

	if !doCoordinator {
		fmt.Println("Nothing to do.")
		return
	}

	server := &coordinator.Server{
		Service:     service,
		PersistPath: servicePersistPath,
	}
	err := server.Persist()
	if err != nil {
		log.Fatalf("failed to create coordinator server state for service %q: %s", service, err)
	}

	fmt.Printf("! Wrote coordinator server state: %s\n", servicePersistPath)
}

func initCoordinator(confPath string) {
	fmt.Printf("--> Generating coordinator key pair and config.\n")
	if cmdutil.Overwrite(confPath) {
		data := cmdconf.NewCoordinatorConfig().TOML()
		err := ioutil.WriteFile(confPath, data, 0600)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("! Wrote new config file: %s\n", confPath)
		fmt.Printf("--> Please edit the config file before running the server.\n")
	}

	initService("Convo")
}

func main() {
	flag.Parse()

	err := os.MkdirAll(*persistPath, 0700)
	if err != nil {
		log.Fatal(err)
	}
	confPath := filepath.Join(*persistPath, "coordinator.conf")

	if *doInit {
		initCoordinator(confPath)
		return
	}

	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(cmdconf.CoordinatorConfig)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %s: %s", confPath, err)
	}

	logsDir := filepath.Join(*persistPath, "logs")
	logHandler, err := vzlog.NewProductionOutput(logsDir)
	if err != nil {
		log.Fatal(err)
	}

	convoPresistPath := filepath.Join(*persistPath, "convo-coordinator-state")
	convoServer := &coordinator.Server{
		Service:    "Convo",
		PrivateKey: conf.PrivateKey,

		ConfigClient: config.StdClient,

		RoundDelay: conf.RoundDelay,

		PersistPath: convoPresistPath,
	}
	err = convoServer.LoadPersistedState()
	if err != nil {
		log.Fatalf("error loading persisted state: %s", err)
	}

	http.Handle("/convo/", http.StripPrefix("/convo", convoServer))

	listener, err := edtls.Listen("tcp", conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls listen: %s", err)
	}

	log.Infof("Listening on %q; logging to %s", conf.ListenAddr, logHandler.Name())
	log.StdLogger.EntryHandler = logHandler
	log.Infof("Listening on %q", conf.ListenAddr)

	err = convoServer.Run()
	if err != nil {
		log.Fatalf("error starting convo loop: %s", err)
	}
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatal(err)
	}
}
