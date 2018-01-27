package convo

import (
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/vuvuzela/mixnet"
)

func TestMarshalConvoConfig(t *testing.T) {
	guardianPub, guardianPriv, _ := ed25519.GenerateKey(rand.Reader)

	conf := &config.SignedConfig{
		Version: config.SignedConfigVersion,

		// need to round otherwise the time includes a monotonic clock value
		Created: time.Now().Round(0),
		Expires: time.Now().Round(0),

		Guardians: []config.Guardian{
			{
				Username: "david",
				Key:      guardianPub,
			},
		},

		Service: "Convo",
		Inner: &ConvoConfig{
			Version: ConvoConfigVersion,

			Coordinator: CoordinatorConfig{
				Key:     guardianPub,
				Address: "localhost:8080",
			},
			MixServers: []mixnet.PublicServerConfig{
				{
					Key:     guardianPub,
					Address: "localhost:1234",
				},
			},
		},
	}
	sig := ed25519.Sign(guardianPriv, conf.SigningMessage())
	conf.Signatures = map[string][]byte{
		base32.EncodeToString(guardianPub): sig,
	}
	if err := conf.Verify(); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}

	conf2 := new(config.SignedConfig)
	err = json.Unmarshal(data, conf2)
	if err != nil {
		t.Fatal(err)
	}

	if conf.Hash() != conf2.Hash() {
		t.Fatalf("round-trip failed:\nbefore=%#v\nafter=%#v\n", *conf, *conf2)
	}
	if !reflect.DeepEqual(conf, conf2) {
		t.Fatalf("round-trip failed:\nbefore=%#v\nafter=%#v\n", *conf, *conf2)
	}
}
