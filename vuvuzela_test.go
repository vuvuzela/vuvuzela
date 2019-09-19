package vuvuzela

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/config"
	alpenhornCoordinator "vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/internal/debug"
	sharedMock "vuvuzela.io/internal/mock"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/coordinator"
	"vuvuzela.io/vuvuzela/internal/mock"
)

type universe struct {
	VuvuzelaDir     string
	AlpenhornDir    string
	Handler         *mockHandler
	ConfigClient    *config.Client
	ConfigServer    *config.Server
	ConvoConfig     *config.SignedConfig
	AddFriendConfig *config.SignedConfig
	DialingConfig   *config.SignedConfig
	GuardianPub     ed25519.PublicKey
	GuardianPriv    ed25519.PrivateKey
	CoordinatorPub  ed25519.PublicKey
}

func (u *universe) Destroy() error {
	// TODO close everything else
	err := os.RemoveAll(u.AlpenhornDir)
	if err != nil {
		return err
	}
	return os.RemoveAll(u.VuvuzelaDir)
}

func createVuvuzelaUniverse() *universe {
	var err error

	u := new(universe)

	u.VuvuzelaDir = filepath.Join("/tmp", ".vuvuzela")
	if err = os.MkdirAll(u.VuvuzelaDir, 0700); err != nil {
		log.Panicf("os.MkdirAll: %s", err)
	}

	u.ConfigServer, u.ConfigClient = sharedMock.LaunchConfigServer(u.VuvuzelaDir)

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
		RoundDelay:   800 * time.Millisecond,
		PersistPath:  filepath.Join(u.VuvuzelaDir, "convo-coordinator-state"),
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

func (u *universe) createAlpenhornUniverse() {
	dir, err := ioutil.TempDir("", "alpenhorn_universe_")
	if err != nil {
		log.Panicf("ioutil.TempDir: %s", err)
	}
	u.AlpenhornDir = dir

	coordinatorPublic, coordinatorPrivate, _ := ed25519.GenerateKey(rand.Reader)
	coordinatorKey := coordinatorPublic
	coordinatorListener, err := edtls.Listen("tcp", "localhost:0", coordinatorPrivate)
	if err != nil {
		log.Panicf("edtls.Listen: %s", err)
	}
	coordinatorAddr := coordinatorListener.Addr().String()

	CDN := sharedMock.LaunchCDN(u.AlpenhornDir, coordinatorPublic)

	mixchain := sharedMock.LaunchMixchain(3, coordinatorPublic)

	PKGs := make([]*sharedMock.PKG, 3)
	for i := range PKGs {
		srv, err := sharedMock.LaunchPKG(coordinatorPublic, func(username string, token string) error {
			return nil
		})
		if err != nil {
			log.Panicf("launching PKG: %s", err)
		}
		PKGs[i] = srv
	}

	u.AddFriendConfig = &config.SignedConfig{
		Version: config.SignedConfigVersion,
		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		Service: "AddFriend",
		Inner: &config.AddFriendConfig{
			Version: config.AddFriendConfigVersion,
			Coordinator: config.CoordinatorConfig{
				Key:     coordinatorKey,
				Address: coordinatorAddr,
			},
			PKGServers: make([]pkg.PublicServerConfig, len(PKGs)),
			MixServers: mixchain.Servers,
			CDNServer: config.CDNServerConfig{
				Key:     CDN.PublicKey,
				Address: CDN.Addr,
			},
		},
	}
	for i, pkgServer := range PKGs {
		u.AddFriendConfig.Inner.(*config.AddFriendConfig).PKGServers[i] = pkgServer.PublicServerConfig
	}

	err = u.ConfigServer.SetCurrentConfig(u.AddFriendConfig)
	if err != nil {
		log.Panicf("error setting current addfriend config: %s", err)
	}

	addFriendServer := &alpenhornCoordinator.Server{
		Service:    "AddFriend",
		PrivateKey: coordinatorPrivate,
		Log: log.WithFields(log.Fields{
			"tag":     "coordinator",
			"service": "AddFriend",
		}),

		ConfigClient: u.ConfigClient,

		PKGWait:      1 * time.Second,
		MixWait:      1 * time.Second,
		RoundWait:    2 * time.Second,
		NumMailboxes: 1,

		PersistPath: filepath.Join(u.AlpenhornDir, "addfriend-coordinator-state"),
	}
	if err := addFriendServer.Persist(); err != nil {
		log.Panicf("error persisting addfriend server: %s", err)
	}
	if err := addFriendServer.LoadPersistedState(); err != nil {
		log.Panicf("error loading persisted state: %s", err)
	}
	if err := addFriendServer.Run(); err != nil {
		log.Panicf("starting addfriend loop: %s", err)
	}

	u.DialingConfig = &config.SignedConfig{
		Version: config.SignedConfigVersion,
		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		Service: "Dialing",
		Inner: &config.DialingConfig{
			Version: config.DialingConfigVersion,
			Coordinator: config.CoordinatorConfig{
				Key:     coordinatorKey,
				Address: coordinatorAddr,
			},
			MixServers: mixchain.Servers,
			CDNServer: config.CDNServerConfig{
				Key:     CDN.PublicKey,
				Address: CDN.Addr,
			},
		},
	}
	err = u.ConfigServer.SetCurrentConfig(u.DialingConfig)
	if err != nil {
		log.Panicf("error setting current dialing config: %s", err)
	}

	dialingServer := &alpenhornCoordinator.Server{
		Service:    "Dialing",
		PrivateKey: coordinatorPrivate,
		Log: log.WithFields(log.Fields{
			"tag":     "coordinator",
			"service": "Dialing",
		}),

		ConfigClient: u.ConfigClient,

		MixWait:      1 * time.Second,
		RoundWait:    2 * time.Second,
		NumMailboxes: 1,

		PersistPath: filepath.Join(u.AlpenhornDir, "dialing-coordinator-state"),
	}
	if err := dialingServer.Persist(); err != nil {
		log.Panicf("error persisting dialing server: %s", err)
	}
	if err := dialingServer.LoadPersistedState(); err != nil {
		log.Panicf("error loading persisted state: %s", err)
	}
	if err := dialingServer.Run(); err != nil {
		log.Panicf("starting dialing loop: %s", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/addfriend/", http.StripPrefix("/addfriend", addFriendServer))
	mux.Handle("/dialing/", http.StripPrefix("/dialing", dialingServer))
	coordinatorHTTPServer := &http.Server{
		Handler: mux,
	}
	go func() {
		err := coordinatorHTTPServer.Serve(coordinatorListener)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()
}

// createUser creates a test client. It is based on main.generateVuvuzelaClient.
func (u *universe) createUser(name string) *Client {

	client := &Client{
		PersistPath:        filepath.Join(u.VuvuzelaDir, fmt.Sprintf("%s-vuvuzela-client-state", name)),
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

type alpenhornClientHandler struct {
	errPrefix string

	confirmedFriend       chan *alpenhorn.Friend
	sentFriendRequest     chan *alpenhorn.OutgoingFriendRequest
	receivedFriendRequest chan *alpenhorn.IncomingFriendRequest
	sentCall              chan *alpenhorn.OutgoingCall
	receivedCall          chan *alpenhorn.IncomingCall
	newConfig             chan []*config.SignedConfig
}

func newAlpenhornHandler(errPrefix string) *alpenhornClientHandler {
	return &alpenhornClientHandler{
		errPrefix:             errPrefix,
		confirmedFriend:       make(chan *alpenhorn.Friend, 1),
		sentFriendRequest:     make(chan *alpenhorn.OutgoingFriendRequest, 1),
		receivedFriendRequest: make(chan *alpenhorn.IncomingFriendRequest, 1),
		sentCall:              make(chan *alpenhorn.OutgoingCall, 1),
		receivedCall:          make(chan *alpenhorn.IncomingCall, 1),
		newConfig:             make(chan []*config.SignedConfig, 1),
	}
}

func (h *alpenhornClientHandler) Error(err error) {
	log.Errorf(h.errPrefix+": client error: %s", err)
}
func (h *alpenhornClientHandler) ConfirmedFriend(f *alpenhorn.Friend) {
	h.confirmedFriend <- f
}
func (h *alpenhornClientHandler) SentFriendRequest(r *alpenhorn.OutgoingFriendRequest) {
	h.sentFriendRequest <- r
}
func (h *alpenhornClientHandler) ReceivedFriendRequest(r *alpenhorn.IncomingFriendRequest) {
	h.receivedFriendRequest <- r
}
func (h *alpenhornClientHandler) SendingCall(call *alpenhorn.OutgoingCall) {
	h.sentCall <- call
}
func (h *alpenhornClientHandler) ReceivedCall(call *alpenhorn.IncomingCall) {
	h.receivedCall <- call
}
func (h *alpenhornClientHandler) NewConfig(configs []*config.SignedConfig) {
	h.newConfig <- configs
}
func (h *alpenhornClientHandler) UnexpectedSigningKey(in *alpenhorn.IncomingFriendRequest, out *alpenhorn.OutgoingFriendRequest) {
	log.Fatalf("unexpected signing key for %s", in.Username)
}

func (u *universe) createAlpenhornClient(name string) *alpenhorn.Client {
	alpenhornStatePath := filepath.Join(u.VuvuzelaDir, fmt.Sprintf("%s-alpenhorn-client-state", name))
	keywheelPath := filepath.Join(u.VuvuzelaDir, fmt.Sprintf("%s-keywheel", name))

	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	client := &alpenhorn.Client{
		Username:           name,
		LongTermPrivateKey: privateKey,
		LongTermPublicKey:  publicKey,
		ConfigClient:       u.ConfigClient,
		Handler:            newAlpenhornHandler(name),

		// For now, reuse the long term key for the PKG login key.
		PKGLoginKey: privateKey,

		ClientPersistPath:   alpenhornStatePath,
		KeywheelPersistPath: keywheelPath,
	}
	err := client.Bootstrap(
		u.AddFriendConfig,
		u.DialingConfig,
	)
	if err != nil {
		log.Fatalf("client.Bootstrap: %s", err)
	}
	err = client.Persist()
	if err != nil {
		log.Fatalf("persisting alpenhorn client: %s", err)
	}

	for _, st := range client.PKGStatus() {
		err = client.Register(st.Server, "token")
		if err != nil {
			log.Fatalf("client.Register: %s", err)
		}
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

func TestRunVuvuzela(t *testing.T) {
	// t.Skip("skipping test that runs vuvuzela servers forever")

	u := createVuvuzelaUniverse()
	u.createAlpenhornUniverse()

	client := u.createAlpenhornClient("alice@example.org")

	_, err := client.ConnectAddFriend()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ConnectDialing()
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	_, err = client.SendFriendRequest("alice@example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-client.Handler.(*alpenhornClientHandler).sentFriendRequest
	log.Info("Sent friend request")

	<-client.Handler.(*alpenhornClientHandler).confirmedFriend
	log.Info("Confirmed friend request")

	// Persist new friend
	err = client.Persist()
	if err != nil {
		log.Panicf("persisting alpenhorn client: %s", err)
	}

	client.CloseAddFriend()
	client.CloseDialing()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt)

	log.Infof("Running Vuvuzela locally with config servers at %s...", u.ConfigClient.ConfigServerURL)
	log.Infof("Press Ctrl+C to close.")

	<-sigchan
	log.Info("Closing...")
	// Give time for goroutines to finish before pulling the rug out from under them
	time.Sleep(1 * time.Second)
	u.Destroy()
	log.Info("Closed.")
}
