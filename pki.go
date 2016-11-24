package vuvuzela

import (
	"net"
	"strings"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/crypto/onionbox"
	. "vuvuzela.io/vuvuzela/internal"
)

type ServerInfo struct {
	Address   string
	PublicKey *BoxKey
}

type PKI struct {
	People      map[string]*BoxKey
	Servers     map[string]*ServerInfo
	ServerOrder []string
	EntryServer string
}

func ReadPKI(jsonPath string) *PKI {
	pki := new(PKI)
	ReadJSONFile(jsonPath, pki)
	if len(pki.ServerOrder) == 0 {
		log.Fatalf("%q: ServerOrder must contain at least one server", jsonPath)
	}
	for _, s := range pki.ServerOrder {
		info, ok := pki.Servers[s]
		if !ok {
			log.Fatalf("%q: server %q not found", jsonPath, s)
		}
		addr := info.Address
		if addr == "" {
			log.Fatalf("%q: server %q does not specify an Address", jsonPath, s)
		}

		if strings.IndexByte(addr, ':') == -1 {
			info.Address = net.JoinHostPort(addr, DefaultServerPort)
		}
	}
	return pki
}

func (pki *PKI) ServerKeys() BoxKeys {
	keys := make([]*BoxKey, 0, 3)
	for _, s := range pki.ServerOrder {
		info := pki.Servers[s]
		keys = append(keys, info.PublicKey)
	}
	return keys
}

func (pki *PKI) FirstServer() string {
	s := pki.ServerOrder[0]
	return pki.Servers[s].Address
}

func (pki *PKI) LastServer() string {
	s := pki.ServerOrder[len(pki.ServerOrder)-1]
	return pki.Servers[s].Address
}

func (pki *PKI) Index(serverName string) int {
	for i, s := range pki.ServerOrder {
		if s == serverName {
			return i
		}
	}
	log.Fatalf("pki.Index: server %q not found", serverName)
	return -1
}

func (pki *PKI) NextServer(serverName string) string {
	i := pki.Index(serverName)
	if i < len(pki.ServerOrder)-1 {
		s := pki.ServerOrder[i+1]
		return pki.Servers[s].Address
	} else {
		return ""
	}
}

func (pki *PKI) NextServerKeys(serverName string) BoxKeys {
	i := pki.Index(serverName)
	var keys []*BoxKey
	for _, s := range pki.ServerOrder[i+1:] {
		keys = append(keys, pki.Servers[s].PublicKey)
	}
	return keys
}

func (pki *PKI) IncomingOnionOverhead(serverName string) int {
	i := len(pki.ServerOrder) - pki.Index(serverName)
	return i * onionbox.Overhead
}

func (pki *PKI) OutgoingOnionOverhead(serverName string) int {
	i := len(pki.ServerOrder) - pki.Index(serverName)
	return i * box.Overhead
}
