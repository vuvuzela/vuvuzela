package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/davidlazar/gocui"

	"vuvuzela.io/alpenhorn"
	. "vuvuzela.io/vuvuzela"
	. "vuvuzela.io/vuvuzela/internal"
)

type GuiClient struct {
	pki    *PKI
	myName string

	gui             *gocui.Gui
	convoClient     *Client
	alpenhornClient *alpenhorn.Client

	mu            sync.Mutex
	selectedConvo *Conversation
	conversations map[string]*Conversation
}

func (gc *GuiClient) switchConversation(peer string, key *[32]byte) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	var convo *Conversation
	convo, ok := gc.conversations[peer]
	if !ok {
		convo = &Conversation{
			pki:          gc.pki,
			myUsername:   gc.myName,
			peerUsername: peer,
			gui:          gc,
		}
		convo.Init()
		gc.conversations[peer] = convo
	}
	if key == nil {
		key = new([32]byte)
		rand.Read(key[:])
	}
	convo.secretKey = key

	gc.selectedConvo = convo
	gc.activateConvo(convo)
	gc.Warnf("Now talking to %s\n", peer)
}

func (gc *GuiClient) activateConvo(convo *Conversation) {
	if gc.convoClient != nil {
		convo.Lock()
		convo.lastPeerResponding = false
		convo.lastLatency = 0
		convo.Unlock()
		gc.convoClient.SetConvoHandler(convo)
	}
}

var commands = map[string]func(*GuiClient, []string) error{
	"quit": func(_ *GuiClient, _ []string) error {
		return gocui.Quit
	},

	"list": func(gc *GuiClient, _ []string) error {
		friends := gc.alpenhornClient.GetFriends()
		if len(friends) > 0 {
			mv, err := gc.gui.View("main")
			if err != nil {
				return err
			}

			fmt.Fprintf(mv, "--- Friend List ---\n")
			tw := tabwriter.NewWriter(mv, 0, 0, 1, ' ', 0)
			for i, friend := range friends {
				keyRound, key := friend.UnsafeKeywheelState()
				keyStr := base64.RawURLEncoding.EncodeToString(key[:])[:12]
				fmt.Fprintf(tw, "%d.\t%s\t{%d|%s...}\n", i, friend.Username, keyRound, keyStr)
			}
			tw.Flush()
			gc.gui.Flush()
		} else {
			gc.Warnf("No friends in your address book.\n")
		}

		return nil
	},

	"call": func(gc *GuiClient, args []string) error {
		if len(args) != 1 {
			gc.Warnf("Missing username\n")
			return nil
		}

		username := args[0]
		friend := gc.alpenhornClient.GetFriend(username)
		if friend == nil {
			gc.Warnf("Friend not found: %s\n", username)
			return nil
		}

		_ = friend.Call(0)
		gc.Warnf("Calling %s ...\n", username)
		return nil
	},

	"addfriend": func(gc *GuiClient, args []string) error {
		if len(args) != 1 {
			gc.Warnf("Missing username\n")
			return nil
		}

		username := args[0]
		_, _ = gc.alpenhornClient.SendFriendRequest(username, nil)
		gc.Warnf("Queued friend request: %s\n", username)
		return nil
	},
}

func (gc *GuiClient) handleLine(line string) error {
	if line[0] == '/' {
		args := strings.Fields(line[1:])
		if len(args) == 0 {
			args = []string{""}
		}

		handler, ok := commands[args[0]]
		if !ok {
			gc.Warnf("Unknown command: %s\n", args[0])
			validCmds := make([]string, 0)
			for cmd, _ := range commands {
				validCmds = append(validCmds, cmd)
			}
			sort.Strings(validCmds)
			gc.Warnf("Valid commands: %v\n", validCmds)
		} else {
			return handler(gc, args[1:])
		}
	} else {
		if gc.selectedConvo.QueueTextMessage([]byte(line)) {
			gc.Printf("<%s> %s\n", gc.myName, line)
		} else {
			gc.Warnf("Queue full, message not sent to %s: %s\n", gc.myName, line)
		}
	}

	return nil
}

func (gc *GuiClient) tabComplete(_ *gocui.Gui, v *gocui.View) error {
	line := strings.TrimRight(v.Buffer(), "\n")
	if line == "" {
		return nil
	}

	if line[0] != '/' || line[len(line)-1] == ' ' {
		return nil
	}

	choices := make([]string, 0)
	args := strings.Fields(line[1:])
	if len(args) == 0 {
		return nil
	}

	if len(args) == 1 {
		for cmd, _ := range commands {
			choices = append(choices, cmd)
		}
	} else {
		for _, friend := range gc.alpenhornClient.GetFriends() {
			choices = append(choices, friend.Username)
		}
	}

	prefix := args[len(args)-1]
	completion, match := completePrefix(prefix, choices)
	if !match {
		return nil
	}

	fmt.Fprintf(v, "%s ", completion)
	v.MoveCursor(len(completion)+1, 0, true)
	return nil
}

func completePrefix(prefix string, choices []string) (string, bool) {
	match := prefix
	nmatches := 0

	for _, choice := range choices {
		if strings.HasPrefix(choice, prefix) {
			match = choice[len(prefix):]
			nmatches += 1
		}
	}

	if nmatches == 1 {
		return match, true
	} else {
		return "", false
	}
}

func (gc *GuiClient) readLine(_ *gocui.Gui, v *gocui.View) error {
	line := strings.TrimRight(v.Buffer(), "\n")
	if line == "" {
		return nil
	}

	v.EditNewLine()
	v.MoveCursor(0, -1, true)
	v.Clear()

	return gc.handleLine(line)
}

func (gc *GuiClient) Flush() {
	gc.gui.Flush()
}

func (gc *GuiClient) Warnf(format string, v ...interface{}) {
	mv, err := gc.gui.View("main")
	if err != nil {
		return
	}
	fmt.Fprintf(mv, "-!- "+format, v...)
	gc.gui.Flush()
}

func (gc *GuiClient) Printf(format string, v ...interface{}) {
	mv, err := gc.gui.View("main")
	if err != nil {
		return
	}
	fmt.Fprintf(mv, format, v...)
	gc.gui.Flush()
}

func (gc *GuiClient) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("main", 0, -1, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrorUnkView {
			return err
		}
		v.Autoscroll = true
		v.Wrap = true
		v.Frame = false
		log.AddHook(gc)
		log.SetOutput(ioutil.Discard)
		log.SetFormatter(&GuiFormatter{})
	}
	sv, err := g.SetView("status", -1, maxY-3, maxX, maxY-1)
	if err != nil {
		if err != gocui.ErrorUnkView {
			return err
		}
		sv.Wrap = false
		sv.Frame = false
		sv.BgColor = gocui.ColorBlue
		sv.FgColor = gocui.ColorWhite
	}
	sv.Clear()

	st := gc.selectedConvo.Status()
	latency := fmt.Sprintf("%.1fs", st.Latency)
	if st.Latency == 0.0 {
		latency = "-"
	}
	round := fmt.Sprintf("%d", st.Round)
	if st.Round == 0 {
		round = "-"
	}
	fmt.Fprintf(sv, " [%s]  [round: %s]  [latency: %s]", gc.myName, round, latency)

	partner := "(no partner)"
	if !gc.selectedConvo.Solo() {
		partner = gc.selectedConvo.peerUsername
	}

	pv, err := g.SetView("partner", -1, maxY-2, len(partner)+1, maxY)
	if err != nil {
		if err != gocui.ErrorUnkView {
			return err
		}
		pv.Wrap = false
		pv.Frame = false
	}
	pv.Clear()

	if st.PeerResponding {
		pv.FgColor = gocui.ColorGreen
	} else {
		pv.FgColor = gocui.ColorRed
	}
	fmt.Fprintf(pv, "%s>", partner)

	if v, err := g.SetView("input", len(partner)+1, maxY-2, maxX, maxY); err != nil {
		if err != gocui.ErrorUnkView {
			return err
		}
		v.Editable = true
		v.Wrap = false
		v.Frame = false
		if err := g.SetCurrentView("input"); err != nil {
			return err
		}
	}

	return nil
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.Quit
}

func (gc *GuiClient) Connect() {
	if err := gc.alpenhornClient.Connect(); err != nil {
		gc.Warnf("Failed to connect to alpenhorn service: %s\n", err)
	}
	gc.Warnf("Connected to alpenhorn service.\n")

	if err := gc.convoClient.Connect(); err != nil {
		gc.Warnf("Failed to connect to convo service: %s\n", err)
		return
	}
	gc.Warnf("Connected to convo service.\n")
}

func (gc *GuiClient) Run() {
	gui := gocui.NewGui()
	if err := gui.Init(); err != nil {
		log.Panicln(err)
	}
	defer gui.Close()
	gc.gui = gui

	if err := gui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}
	if err := gui.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, gc.readLine); err != nil {
		log.Panicln(err)
	}
	if err := gui.SetKeybinding("input", gocui.KeyTab, gocui.ModNone, gc.tabComplete); err != nil {
		log.Panicln(err)
	}
	gui.ShowCursor = true
	gui.BgColor = gocui.ColorDefault
	gui.FgColor = gocui.ColorDefault
	gui.SetLayout(gc.layout)

	gc.conversations = make(map[string]*Conversation)
	// We need an active conversation to render the GUI
	// and to connect to the convo service.
	gc.switchConversation(gc.myName, nil)

	go func() {
		time.Sleep(500 * time.Millisecond)
		gc.Connect()
	}()

	gocui.Edit = vuvuzelaEditor
	err := gui.MainLoop()
	if err != nil && err != gocui.Quit {
		log.Panicln(err)
	}
}

func (gc *GuiClient) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}

	gc.Warnf(line)
	return nil
}

func (gc *GuiClient) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
	}
}

func vuvuzelaEditor(v *gocui.View, key gocui.Key, ch rune, mod gocui.Modifier) {
	switch {
	case ch != 0 && mod == 0:
		v.EditWrite(ch)
	case key == gocui.KeySpace:
		v.EditWrite(' ')
	case key == gocui.KeyBackspace || key == gocui.KeyBackspace2:
		v.EditDelete(true)
	case key == gocui.KeyDelete:
		v.EditDelete(false)
	case key == gocui.KeyInsert:
		v.Overwrite = !v.Overwrite
	case key == gocui.KeyArrowLeft:
		v.MoveCursor(-1, 0, true)
	case key == gocui.KeyArrowRight:
		v.MoveCursor(1, 0, true)
	}
}
