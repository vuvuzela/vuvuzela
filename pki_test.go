package vuvuzela

import (
	"testing"
)

func Key(s string) *BoxKey {
	k, err := KeyFromString(s)
	if err != nil {
		panic(err)
	}
	return k
}

var testPKI = &PKI{
	People: map[string]*BoxKey{
		"david": Key("st50pjmxgzv6pybrnxrxjd330s8hf37g5gzs1dqywy4bw3kdvcgg"),
		"alice": Key("j10hpqtgnqc1y21xp5y7yamwa32jvdp89888q2semnxg95j4v82g"),
	},
	Servers: map[string]*ServerInfo{
		"openstack1": {
			Address:   "localhost",
			PublicKey: Key("pd04y1ryrfxtrayjg9f4cfsw1ayfhwrcfd7g7emhfjrsc4cd20f0"),
		},
		"openstack2": {
			Address:   "localhost:2719",
			PublicKey: Key("fkaf8ds0a4fmdsztqzpcn4em9npyv722bxv2683n9fdydzdjwgy0"),
		},
	},
	ServerOrder: []string{"openstack1", "openstack2"},
}

func TestNextKeys(t *testing.T) {
	nextKeys := testPKI.NextServerKeys("openstack1")
	if len(nextKeys) != 1 {
		t.Fatalf("wrong length")
	}
	if nextKeys[0] != testPKI.Servers["openstack2"].PublicKey {
		t.Fatalf("wrong key")
	}
}
