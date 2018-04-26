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
	"os/user"
	"path/filepath"
	"strings"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/vuvuzela/cmd/cmdconf"
	"vuvuzela.io/vuvuzela/coordinator"
	"vuvuzela.io/vuvuzela/internal/vzlog"
)

var (
	doInit = flag.Bool("init", false, "initialize a coordinator for the first time")
)

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
	data := cmdconf.NewCoordinatorConfig().TOML()
	err := ioutil.WriteFile(path, data, 0600)
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
	conf := new(cmdconf.CoordinatorConfig)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %s: %s", confPath, err)
	}

	logHandler, err := vzlog.NewProductionOutput(conf.LogsDir)
	if err != nil {
		log.Fatal(err)
	}

	coordinatorPresistPath := filepath.Join(confHome, "convo-coordinator-state")
	convoServer := &coordinator.Server{
		Service:    "Convo",
		PrivateKey: conf.PrivateKey,

		ConfigClient: config.StdClient,

		RoundDelay: conf.RoundDelay,

		PersistPath: coordinatorPresistPath,
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
