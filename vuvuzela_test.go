package vuvuzela

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/internal/debug"
	sharedMock "vuvuzela.io/internal/mock"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/coordinator"
	"vuvuzela.io/vuvuzela/internal/mock"
)

type universe struct {
	Dir            string
	Handler        *mockHandler
	ConfigClient   *config.Client
	ConfigServer   *config.Server
	ConvoConfig    *config.SignedConfig
	GuardianPub    ed25519.PublicKey
	GuardianPriv   ed25519.PrivateKey
	CoordinatorPub ed25519.PublicKey
}

func (u *universe) Destroy() error {
	// TODO close everything else
	return os.RemoveAll(u.Dir)
}

func createVuvuzelaUniverse() *universe {
	var err error

	u := new(universe)

	u.Dir, err = ioutil.TempDir("", "vuvuzela_universe_")
	if err != nil {
		log.Panicf("ioutil.TempDir: %s", err)
	}

	u.ConfigServer, u.ConfigClient = sharedMock.LaunchConfigServer(u.Dir)

	coordinatorPub, coordinatorPriv, err := ed25519.GenerateKey(rand.Reader)
	u.CoordinatorPub = coordinatorPub
	if err != nil {
		log.Panicf("ed25519.GenerateKey: %s", err)
	}
	u.GuardianPub, u.GuardianPriv, _ = ed25519.GenerateKey(rand.Reader)

	coordinatorListener, err := edtls.Listen("tcp", "localhost:0", coordinatorPriv)
	if err != nil {
		log.Panicf("edtls.Listen: %s", err)
	}

	mixchain := mock.LaunchMixchain(3, coordinatorPub)
	conf := &config.SignedConfig{
		Version: config.SignedConfigVersion,
		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		Guardians: []config.Guardian{
			{
				Username: "guardian",
				Key:      u.GuardianPub,
			},
		},

		Service: "Convo",
		Inner: &convo.ConvoConfig{
			Version: convo.ConvoConfigVersion,
			Coordinator: convo.CoordinatorConfig{
				Key:     coordinatorPub,
				Address: coordinatorListener.Addr().String(),
			},
			MixServers: mixchain.Servers,
		},
	}
	sig := ed25519.Sign(u.GuardianPriv, conf.SigningMessage())
	conf.Signatures = map[string][]byte{
		base32.EncodeToString(u.GuardianPub): sig,
	}
	err = u.ConfigServer.SetCurrentConfig(conf)
	if err != nil {
		log.Panicf("setting current config: %s", err)
	}

	u.ConvoConfig, err = u.ConfigClient.CurrentConfig("Convo")
	if err != nil {
		log.Panicf("fetching latest convo config: %s", err)
	}

	deadDrop := new(convo.DeadDrop)
	_, err = rand.Read(deadDrop[:])
	if err != nil {
		log.Panicf("Failed to make random dead drop: %s", err)
	}

	u.Handler = &mockHandler{
		errPrefix:      "[ERROR]",
		sentReplies:    make(chan roundAndReplies, 1),
		newConfig:      make(chan []*config.SignedConfig, 1),
		sentOutgoing:   make(chan roundAndDeadDropMsgs, 1),
		agreedDeadDrop: deadDrop,
	}

	convoServer := &coordinator.Server{
		Service:      "Convo",
		PrivateKey:   coordinatorPriv,
		ConfigClient: u.ConfigClient,
		RoundDelay:   250 * time.Millisecond,
		PersistPath:  filepath.Join(u.Dir, "convo-coordinator-state"),
	}

	http.Handle("/convo/", http.StripPrefix("/convo", convoServer))

	err = convoServer.Run()
	if err != nil {
		log.Panicf("convoServer.Run: %s", err)
	}

	go func() {
		err := http.Serve(coordinatorListener, nil)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()

	return u
}

// createUser creates a test client
// (without writing it to disk). It is based on main.generateVuvuzelaClient.
func (u *universe) createUser(name string) *Client {

	client := &Client{
		PersistPath:        filepath.Join(u.Dir, fmt.Sprintf("%s-client", name)),
		ConfigClient:       u.ConfigClient,
		Handler:            u.Handler,
		CoordinatorLatency: 150 * time.Millisecond,
	}
	err := client.Bootstrap(u.ConvoConfig)
	if err != nil {
		log.Panicf("bootstrapping vuvuzela client: %s", err)
	}
	err = client.Persist()
	if err != nil {
		log.Panicf("persisting vuvuzela client: %s", err)
	}
	return client
}

type mockHandler struct {
	errPrefix      string
	sentReplies    chan roundAndReplies
	newConfig      chan []*config.SignedConfig
	sentOutgoing   chan roundAndDeadDropMsgs
	agreedDeadDrop *convo.DeadDrop
}

type roundAndReplies struct {
	round   uint32
	replies [][]byte
}

type roundAndDeadDropMsgs struct {
	round    uint32
	messages []*convo.DeadDropMessage
}

// Outgoing sends a random message to the agreed dead drop.
func (h *mockHandler) Outgoing(round uint32) []*convo.DeadDropMessage {
	out := make([]*convo.DeadDropMessage, 0, 1)
	msg := new(convo.DeadDropMessage)
	msg.DeadDrop = *h.agreedDeadDrop
	rand.Read(msg.EncryptedMessage[:])
	out = append(out, msg)
	h.sentOutgoing <- roundAndDeadDropMsgs{round: round, messages: out}
	return out
}

func (h *mockHandler) Replies(round uint32, replies [][]byte) {
	h.sentReplies <- roundAndReplies{round: round, replies: replies}
}
func (h *mockHandler) NewConfig(chain []*config.SignedConfig) {
	h.newConfig <- chain
}
func (h *mockHandler) Error(err error) {
	log.Errorf(h.errPrefix+": client error: %s", err)
}
func (h *mockHandler) DebugError(err error) {
	log.Errorf(h.errPrefix+": debug client error: %s", err)
}
func (h *mockHandler) GlobalAnnouncement(message string) {
	log.Debugf("GLOBAL ANNOUNCEMENT: %s", message)
}

func TestVuvuzelaConvo(t *testing.T) {
	u := createVuvuzelaUniverse()
	defer func() {
		// Give time for goroutines to finish before pulling the rug out from under them
		time.Sleep(1 * time.Second)
		u.Destroy()
	}()

	aliceClient := u.createUser("alice")
	_, err := aliceClient.ConnectConvo()
	if err != nil {
		t.Fatalf("Failed to connect Alice's conversation: %s", err)
	}
	defer aliceClient.CloseConvo()

	bobClient := u.createUser("bob")
	_, err = bobClient.ConnectConvo()
	if err != nil {
		t.Fatalf("Failed to connect Bob's conversation: %s", err)
	}
	defer bobClient.CloseConvo()

	aliceRoundAndDeadDropMsgs := <-aliceClient.Handler.(*mockHandler).sentOutgoing
	aliceRound := aliceRoundAndDeadDropMsgs.round
	aliceMsgs := aliceRoundAndDeadDropMsgs.messages

	bobRoundAndDeadDropMsgs := <-bobClient.Handler.(*mockHandler).sentOutgoing
	bobRound := bobRoundAndDeadDropMsgs.round
	bobMsgs := bobRoundAndDeadDropMsgs.messages

	aliceRoundAndReplies := <-aliceClient.Handler.(*mockHandler).sentReplies
	aliceReplyRound := aliceRoundAndReplies.round
	aliceReplies := aliceRoundAndReplies.replies

	bobRoundAndReplies := <-bobClient.Handler.(*mockHandler).sentReplies
	bobReplyRound := bobRoundAndReplies.round
	bobReplies := bobRoundAndReplies.replies

	if len(bobMsgs) != len(aliceReplies) {
		t.Fatalf("bob should have as many messages as alice sent")
	}
	if !bytes.Equal(bobMsgs[0].EncryptedMessage[:], aliceReplies[0][:]) {
		t.Fatal("bob's message should be the same as alice's reply")
	}

	if len(aliceMsgs) != len(bobReplies) {
		t.Fatalf("alice should have as many messages as bob sent")
	}
	if !bytes.Equal(aliceMsgs[0].EncryptedMessage[:], bobReplies[0][:]) {
		t.Fatal("alice's message should be the same as bob's reply")
	}

	latestRound, err := aliceClient.LatestRound()
	if err != nil {
		t.Fatalf("Failed to get latest round: %s", err)
	}
	if bobRound > latestRound || aliceRound > latestRound || aliceReplyRound > latestRound || bobReplyRound > latestRound {
		t.Fatalf("Latest round %d should be same or later than %d, %d %d, %d", latestRound, bobRound, aliceRound, aliceReplyRound, bobReplyRound)
	}
}

func TestVuvuzelaConfig(t *testing.T) {
	u := createVuvuzelaUniverse()
	defer func() {
		// Give time for goroutines to finish before pulling the rug out from under them
		time.Sleep(1 * time.Second)
		u.Destroy()
	}()

	user := u.createUser("user")
	_, err := user.ConnectConvo()
	if err != nil {
		t.Fatalf("Failed to connect user's conversation: %s", err)
	}
	defer user.CloseConvo()

	// Deep copy previous convo config
	data, err := json.Marshal(u.ConvoConfig)
	if err != nil {
		t.Fatal(err)
	}

	newConvoConfig := new(config.SignedConfig)
	err = json.Unmarshal(data, newConvoConfig)
	if err != nil {
		t.Fatal(err)
	}

	newConvoConfig.Created = time.Now()
	newConvoConfig.Expires = time.Now().Add(24 * time.Hour)
	newConvoConfig.PrevConfigHash = u.ConvoConfig.Hash()

	newMixchain := mock.LaunchMixchain(2, u.CoordinatorPub)
	newConvoConfig.Inner.(*convo.ConvoConfig).MixServers = newMixchain.Servers

	sig := ed25519.Sign(u.GuardianPriv, newConvoConfig.SigningMessage())
	newConvoConfig.Signatures = map[string][]byte{
		base32.EncodeToString(u.GuardianPub): sig,
	}

	err = u.ConfigClient.SetCurrentConfig(newConvoConfig)
	if err != nil {
		t.Fatal(err)
	}

	confs := <-user.Handler.(*mockHandler).newConfig
	if confs[0].Hash() != newConvoConfig.Hash() {
		t.Fatalf("received unexpected config: %s", debug.Pretty(confs))
	}
}
