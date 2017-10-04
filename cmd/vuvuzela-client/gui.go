package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/jroimartin/gocui"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/log/ansi"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/vuvuzela"
)

type GuiClient struct {
	myName string

	gui             *gocui.Gui
	convoClient     *vuvuzela.Client
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
		return gocui.ErrQuit
	},

	"list": func(gc *GuiClient, _ []string) error {
		mv, err := gc.gui.View("main")
		if err != nil {
			return err
		}

		fmt.Fprintf(mv, " ┌─────────\n")

		inReqs := gc.alpenhornClient.GetIncomingFriendRequests()
		if len(inReqs) > 0 {
			fmt.Fprintf(mv, " │ Incoming Friend Requests\n")
			tw := tabwriter.NewWriter(mv, 0, 0, 1, ' ', 0)
			for _, req := range inReqs {
				key := base32.EncodeToString(req.LongTermKey)
				fmt.Fprintf(tw, " │    %s\t{%s}\n", req.Username, key)
			}
			tw.Flush()
			fmt.Fprintf(mv, " ├─────────\n")
		}

		outReqs := gc.alpenhornClient.GetOutgoingFriendRequests()
		if len(outReqs) > 0 {
			fmt.Fprintf(mv, " │ Outgoing Friend Requests\n")
			tw := tabwriter.NewWriter(mv, 0, 0, 1, ' ', 0)
			for _, req := range outReqs {
				confirm := ""
				if req.Confirmation {
					confirm = "(confirmation)"
				}
				key := "(no key specified)"
				if req.ExpectedKey != nil {
					key = "{" + base32.EncodeToString(req.ExpectedKey) + "}"
				}
				fmt.Fprintf(tw, " │    %s\t%s\t%s\n", req.Username, key, confirm)
			}
			tw.Flush()
			fmt.Fprintf(mv, " ├─────────\n")
		}

		friends := gc.alpenhornClient.GetFriends()
		fmt.Fprintf(mv, " │ Friends\n")
		if len(friends) == 0 {
			fmt.Fprintf(mv, " │    no friends; use /addfriend to add a friend\n")
		} else {
			tw := tabwriter.NewWriter(mv, 0, 0, 1, ' ', 0)
			for i, friend := range friends {
				keyRound, key := friend.UnsafeKeywheelState()
				keyStr := base64.RawURLEncoding.EncodeToString(key[:])[:12]
				fmt.Fprintf(tw, " │    %d.\t%s\t{%d|%s...}\n", i, friend.Username, keyRound, keyStr)
			}
			tw.Flush()
		}
		fmt.Fprintf(mv, " └─────────\n")

		return nil
	},

	"call": func(gc *GuiClient, args []string) error {
		if len(args) == 0 {
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
		if len(args) == 0 {
			gc.Warnf("Missing username\n")
			return nil
		}

		username := args[0]
		_, _ = gc.alpenhornClient.SendFriendRequest(username, nil)
		gc.Warnf("Queued friend request: %s\n", username)
		return nil
	},

	"delfriend": func(gc *GuiClient, args []string) error {
		if len(args) == 0 {
			gc.Warnf("Missing username\n")
			return nil
		}

		username := args[0]
		u := gc.alpenhornClient.GetFriend(username)
		if u == nil {
			gc.Warnf("Cannot find friend %s\n", username)
		} else {
			u.Remove()
			gc.Warnf("Removed friend %s\n", username)
		}
		return nil
	},

	"approve": func(gc *GuiClient, args []string) error {
		if len(args) == 0 {
			gc.Warnf("Missing username\n")
			return nil
		}
		username := args[0]
		reqs := gc.alpenhornClient.GetIncomingFriendRequests()
		for _, req := range reqs {
			if req.Username == username {
				_, err := req.Approve()
				if err != nil {
					gc.Warnf("error approving friend request: %s\n", err)
					return nil
				}
				gc.Warnf("Approved friend request: %s\n", username)
				return nil
			}
		}
		gc.Warnf("No friend request from %s\n", username)
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

func (gc *GuiClient) redraw() {
	gc.gui.Update(func(gui *gocui.Gui) error {
		return nil
	})
}

func (gc *GuiClient) Warnf(format string, v ...interface{}) {
	gc.gui.Update(func(gui *gocui.Gui) error {
		mv, err := gui.View("main")
		if err != nil {
			return err
		}
		fmt.Fprintf(mv, "-!- "+format, v...)
		return nil
	})
}

func (gc *GuiClient) Printf(format string, v ...interface{}) {
	gc.gui.Update(func(gui *gocui.Gui) error {
		mv, err := gui.View("main")
		if err != nil {
			return err
		}
		fmt.Fprintf(mv, format, v...)
		return nil
	})
}

func (gc *GuiClient) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("main", 0, -1, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Autoscroll = true
		v.Wrap = true
		v.Frame = false
	}
	sv, err := g.SetView("status", -1, maxY-3, maxX, maxY-1)
	if err != nil {
		if err != gocui.ErrUnknownView {
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
		if err != gocui.ErrUnknownView {
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
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Editor = gocui.EditorFunc(vuvuzelaEditor)
		v.Editable = true
		v.Wrap = false
		v.Frame = false
		if _, err := g.SetCurrentView("input"); err != nil {
			return err
		}
	}

	return nil
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (gc *GuiClient) Connect() {
	gc.Register()

	if err := gc.alpenhornClient.Connect(); err != nil {
		gc.Warnf("Failed to connect to alpenhorn service: %s\n", err)
	} else {
		gc.Warnf("Connected to alpenhorn service.\n")
	}

	if err := gc.convoClient.Connect(); err != nil {
		gc.Warnf("Failed to connect to convo service: %s\n", err)
	} else {
		gc.Warnf("Connected to convo service.\n")
	}
}

func (gc *GuiClient) Register() {
	stats := gc.alpenhornClient.PKGStatus()
	for _, st := range stats {
		if st.Error == nil {
			continue
		}

		pkgErr, ok := st.Error.(pkg.Error)
		if ok && pkgErr.Code == pkg.ErrNotRegistered {
			err := gc.alpenhornClient.Register(st.Server)
			if err != nil {
				gc.Warnf("Failed to register with PKG %s: %s\n", st.Server.Address, err)
				continue
			}
			gc.Warnf("Registered %q with PKG %s\n", gc.alpenhornClient.Username, st.Server.Address)
		} else {
			gc.Warnf("Failed to check account status with PKG %s: %s\n", st.Server.Address, st.Error)
		}
	}
}

func (gc *GuiClient) Run() {
	gui, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		panic(err)
	}
	defer gui.Close()
	gc.gui = gui

	gui.SetManagerFunc(gc.layout)

	if err := gui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		panic(err)
	}
	if err := gui.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, gc.readLine); err != nil {
		panic(err)
	}
	if err := gui.SetKeybinding("input", gocui.KeyTab, gocui.ModNone, gc.tabComplete); err != nil {
		panic(err)
	}
	gui.Cursor = true
	gui.BgColor = gocui.ColorDefault
	gui.FgColor = gocui.ColorDefault

	gc.conversations = make(map[string]*Conversation)
	// We need an active conversation to render the GUI
	// and to connect to the convo service.
	gc.switchConversation(gc.myName, nil)

	go func() {
		time.Sleep(500 * time.Millisecond)
		gc.Connect()
	}()

	err = gui.MainLoop()
	if err != nil && err != gocui.ErrQuit {
		panic(err)
	}
}

func (gc *GuiClient) Fire(e *log.Entry) {
	buf := new(bytes.Buffer)
	color := e.Level.Color()
	if e.Level == log.InfoLevel {
		// Colorful timestamps on info messages is too distracting.
		buf.WriteString(e.Time.Format("15:04:05"))
	} else {
		ansi.WriteString(buf, e.Time.Format("15:04:05"), color, ansi.Bold)
	}
	fmt.Fprintf(buf, " %s %-44s ", e.Level.Icon(), e.Message)
	log.Logfmt(buf, e.Fields)
	buf.WriteByte('\n')

	gc.Warnf("%s", buf.Bytes())
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
