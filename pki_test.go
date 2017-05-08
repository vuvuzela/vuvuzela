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
