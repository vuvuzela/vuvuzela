// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"vuvuzela.io/alpenhorn/cmd/cmdutil"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/vuvuzela/cmd/cmdconf"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/internal/vzlog"
	"vuvuzela.io/vuvuzela/mixnet"
	pb "vuvuzela.io/vuvuzela/mixnet/convopb"
)

var (
	doinit      = flag.Bool("init", false, "create config file")
	persistPath = flag.String("persist", "persist_vzmix", "persistent data directory")
)

func writeNewConfig(path string) {
	data := cmdconf.NewMixerConfig().TOML()
	err := ioutil.WriteFile(path, data, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", path)
}

func main() {
	flag.Parse()

	if err := os.MkdirAll(*persistPath, 0700); err != nil {
		log.Fatal(err)
	}
	confPath := filepath.Join(*persistPath, "mixer.conf")

	if *doinit {
		if cmdutil.Overwrite(confPath) {
			writeNewConfig(confPath)
		}
		return
	}

	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(cmdconf.MixerConfig)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %q: %s", confPath, err)
	}

	logsDir := filepath.Join(*persistPath, "logs")
	logHandler, err := vzlog.NewProductionOutput(logsDir)
	if err != nil {
		log.Fatal(err)
	}

	signedConfig, err := config.StdClient.CurrentConfig("Convo")
	if err != nil {
		log.Fatal(err)
	}
	convoConfig := signedConfig.Inner.(*convo.ConvoConfig)

	mixServer := &mixnet.Server{
		SigningKey:     conf.PrivateKey,
		CoordinatorKey: convoConfig.Coordinator.Key,

		Services: map[string]mixnet.MixService{
			"Convo": &convo.ConvoService{
				Laplace:      conf.Noise,
				AccessCounts: make(chan convo.AccessCount, 64),
			},
		},
	}

	if conf.DebugAddr != "" {
		go func() {
			log.Fatal(http.ListenAndServe(conf.DebugAddr, nil))
		}()
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
	}

	creds := credentials.NewTLS(edtls.NewTLSServerConfig(conf.PrivateKey))
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	pb.RegisterMixnetServer(grpcServer, mixServer)

	log.Infof("Listening on %q; logging to %s", conf.ListenAddr, logHandler.Name())
	log.StdLogger.EntryHandler = logHandler
	log.Infof("Listening on %q", conf.ListenAddr)

	listener, err := net.Listen("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalf("net.Listen: %s", err)
	}

	err = grpcServer.Serve(listener)
	log.Fatal(err)
}
