package main

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"

	. "github.com/davidlazar/vuvuzela"
	"github.com/davidlazar/vuvuzela/onionbox"
)

type Dialer struct {
	gui          *GuiClient
	pki          *PKI
	myPublicKey  *BoxKey
	myPrivateKey *BoxKey

	userDialRequests chan *BoxKey
}

func (d *Dialer) Init() {
	d.userDialRequests = make(chan *BoxKey, 4)
}

func (d *Dialer) QueueRequest(publicKey *BoxKey) {
	d.userDialRequests <- publicKey
}

func (d *Dialer) NextDialRequest(round uint32, buckets uint32) *DialRequest {
	var ex *DialExchange
	select {
	case pk := <-d.userDialRequests:
		intro := (&Introduction{
			Rendezvous:  round + 4,
			LongTermKey: *d.myPublicKey,
		}).Marshal()
		ctxt, _ := onionbox.Seal(intro, ForwardNonce(round), BoxKeys{pk}.Keys())
		ex = &DialExchange{
			Bucket: KeyDialBucket(pk, buckets),
		}
		copy(ex.EncryptedIntro[:], ctxt)
	default:
		ex = &DialExchange{
			Bucket: 0,
		}
		rand.Read(ex.EncryptedIntro[:])
	}

	onion, _ := onionbox.Seal(ex.Marshal(), ForwardNonce(round), d.pki.ServerKeys().Keys())

	return &DialRequest{
		Round: round,
		Onion: onion,
	}
}

func (d *Dialer) HandleDialBucket(db *DialBucket) {
	nonce := ForwardNonce(db.Round)

OUTER:
	for _, b := range db.Intros {
		var pk [32]byte
		copy(pk[:], b[0:32])
		data, ok := box.Open(nil, b[32:], nonce, &pk, d.myPrivateKey.Key())
		if !ok {
			continue
		}

		intro := new(Introduction)
		if err := intro.Unmarshal(data); err != nil {
			continue
		}

		for name, key := range d.pki.People {
			if *key == intro.LongTermKey {
				d.gui.Warnf("Received introduction: %s\n", name)
				continue OUTER
			}
		}
		d.gui.Warnf("Received introduction: (%s)\n", &intro.LongTermKey)
	}
}
