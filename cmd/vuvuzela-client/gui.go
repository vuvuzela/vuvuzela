// Copyright 2015 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/jroimartin/gocui"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/log/ansi"
	"vuvuzela.io/vuvuzela"
	"vuvuzela.io/vuvuzela/convo"
)

const NumOutgoing = 5

type GuiClient struct {
	myName string

	gui             *gocui.Gui
	convoClient     *vuvuzela.Client
	alpenhornClient *alpenhorn.Client

	mu            sync.Mutex
	selectedConvo *Conversation
	conversations []*Conversation
	active        map[*Conversation]bool
	pendingRounds map[uint32]pendingRound
	mainUnread    bool

	connectOnce sync.Once
}

type pendingRound struct {
	activeConvos []*Conversation
}

func (gc *GuiClient) Outgoing(round uint32) []*convo.DeadDropMessage {
	out := make([]*convo.DeadDropMessage, 0, NumOutgoing)

	gc.mu.Lock()
	defer gc.mu.Unlock()

	convos := make([]*Conversation, 0, len(gc.active))
	for convo := range gc.active {
		out = append(out, convo.NextMessage(round))
		convos = append(convos, convo)
	}

	for len(out) < NumOutgoing {
		msg := new(convo.DeadDropMessage)
		rand.Read(msg.DeadDrop[:])
		rand.Read(msg.EncryptedMessage[:])
		out = append(out, msg)
	}

	gc.pendingRounds[round] = pendingRound{
		activeConvos: convos,
	}

	return out
}

func (gc *GuiClient) Replies(round uint32, replies [][]byte) {
	gc.mu.Lock()
	st := gc.pendingRounds[round]
	delete(gc.pendingRounds, round)
	gc.mu.Unlock()

	for i, convo := range st.activeConvos {
		convo.Reply(round, replies[i])
	}
}

func (gc *GuiClient) activateConvo(convo *Conversation, wheel *keywheelStart) bool {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if len(gc.active) < NumOutgoing {
		gc.active[convo] = true
		convo.Lock()
		convo.sessionKey = wheel.sessionKey
		convo.sessionKeyRound = wheel.convoRound
		convo.lastPeerResponding = false
		convo.lastLatency = 0
		convo.pendingCall = nil
		convo.lastOut = -1
		convo.Unlock()
		return true
	}

	return false
}

func (gc *GuiClient) deactivateConvo(convo *Conversation) bool {
	gc.mu.Lock()
	if gc.active[convo] {
		delete(gc.active, convo)
		gc.mu.Unlock()
	} else {
		gc.mu.Unlock()
		return false
	}

	return true
}

func (gc *GuiClient) getOrCreateConvo(username string) *Conversation {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	for _, convo := range gc.conversations {
		if convo.peerUsername == username {
			return convo
		}
	}

	convo := &Conversation{
		peerUsername: username,
		myUsername:   gc.myName,
		gc:           gc,
	}
	convo.Init()

	gc.conversations = append(gc.conversations, convo)
	maxX, maxY := gc.gui.Size()
	if err := setConvoView(gc.gui, convo.ViewName(), maxX, maxY); err != nil {
		panic(err)
	}

	return convo
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
			return nil
		}

		return handler.Handler(gc, args[1:])
	}

	gc.mu.Lock()
	convo := gc.selectedConvo
	gc.mu.Unlock()

	if convo == nil {
		gc.Warnf("Try typing a command like /help or /call <username>.\n")
		return nil
	}

	convo.QueueTextMessage([]byte(line))

	return nil
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

// Printf writes a string to the main window and should only be called from
// the Go routine that runs the GUI loop.
func (gc *GuiClient) Printf(format string, v ...interface{}) {
	mv, err := gc.gui.View("main")
	if err != nil {
		return
	}
	fmt.Fprintf(mv, format, v...)

	go func() {
		gc.mu.Lock()
		if gc.selectedConvo != nil {
			gc.mainUnread = true
		}
		gc.mu.Unlock()
	}()
}

// PrintfSync writes a string to the main window and should be called
// from Go routines that are not the GUI loop.
func (gc *GuiClient) PrintfSync(format string, v ...interface{}) {
	done := make(chan struct{})
	gc.gui.Update(func(gui *gocui.Gui) error {
		defer close(done)
		mv, err := gui.View("main")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(mv, format, v...)
		return err
	})

	go func() {
		gc.mu.Lock()
		if gc.selectedConvo != nil {
			gc.mainUnread = true
		}
		gc.mu.Unlock()
	}()

	<-done
}

// warningPrefix is yellow.
var warningPrefix = fmt.Sprintf("%s ", ansi.Colorf("-!-", ansi.Foreground(11)))

func (gc *GuiClient) Warnf(format string, v ...interface{}) {
	gc.Printf(warningPrefix+format, v...)
}

func (gc *GuiClient) WarnfSync(format string, v ...interface{}) {
	gc.PrintfSync(warningPrefix+format, v...)
}

func (gc *GuiClient) focusMain() error {
	gc.mu.Lock()
	prev := gc.selectedConvo
	if prev != nil {
		prev.Lock()
		prev.focused = false
		prev.Unlock()
	}
	gc.selectedConvo = nil
	gc.mainUnread = false
	gc.mu.Unlock()
	return gc.setViewOnTop("main")
}

func (gc *GuiClient) focusConvo(c *Conversation) error {
	gc.mu.Lock()
	prev := gc.selectedConvo
	if prev != nil {
		prev.Lock()
		prev.focused = false
		prev.Unlock()
	}
	gc.selectedConvo = c
	gc.mu.Unlock()

	c.Lock()
	c.unread = false
	c.focused = true
	c.Unlock()

	return gc.setViewOnTop(c.ViewName())
}

func (gc *GuiClient) focusConvoIndex(index int) error {
	if index == 0 {
		return gc.focusMain()
	}

	convoIndex := index - 1
	if convoIndex > len(gc.conversations)-1 {
		return nil
	}

	gc.mu.Lock()
	convo := gc.conversations[convoIndex]
	gc.mu.Unlock()

	return gc.focusConvo(convo)
}

func (gc *GuiClient) setViewOnTop(view string) error {
	_, err := gc.gui.SetViewOnTop(view)
	if err != nil {
		return err
	}
	_, err = gc.gui.SetViewOnTop("status")
	if err != nil {
		return err
	}
	return nil
}

func setConvoView(g *gocui.Gui, name string, maxX, maxY int) error {
	if v, err := g.SetView(name, 0, -1, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Autoscroll = true
		v.Wrap = true
		v.Frame = false
	}
	return nil
}

func (gc *GuiClient) scrollUp(_ *gocui.Gui, _ *gocui.View) error {
	gc.scrollCurrentView(-1)
	// Ignore error, otherwise scrolling up past the top would cause a panic.
	return nil
}
func (gc *GuiClient) scrollDown(_ *gocui.Gui, _ *gocui.View) error {
	gc.scrollCurrentView(1)
	return nil
}
func (gc *GuiClient) scrollCurrentView(dy int) error {
	gc.mu.Lock()
	convo := gc.selectedConvo
	gc.mu.Unlock()

	viewName := "main"
	if convo != nil {
		viewName = convo.ViewName()
	}
	v, err := gc.gui.View(viewName)
	if err != nil {
		return err
	}

	// Scrolling logic copied from https://github.com/jroimartin/gocui/issues/84
	_, y := v.Size()
	ox, oy := v.Origin()

	// If we're at the bottom...
	if oy+dy > strings.Count(v.ViewBuffer(), "\n")-y-1 {
		// Set autoscroll to normal again.
		v.Autoscroll = true
	} else {
		// Set autoscroll to false and scroll.
		v.Autoscroll = false
		return v.SetOrigin(ox, oy+dy)
	}

	return nil
}

func (gc *GuiClient) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if err := setConvoView(g, "main", maxX, maxY); err != nil {
		return err
	}

	gc.mu.Lock()
	defer gc.mu.Unlock()

	for _, convo := range gc.conversations {
		if err := setConvoView(g, convo.ViewName(), maxX, maxY); err != nil {
			return err
		}
	}

	sv, err := g.SetView("status", -1, maxY-3, maxX, maxY-1)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		sv.Wrap = false
		sv.Frame = false
		sv.BgColor = 26
		sv.FgColor = 231
	}
	sv.Clear()

	menu := "1"
	if gc.selectedConvo == nil {
		menu = fmt.Sprintf("%d", ansi.Colorf(1, ansi.Bold))
	} else if gc.mainUnread {
		menu = fmt.Sprintf("%d:main", ansi.Colorf(1, ansi.Green, ansi.Bold))
	}
	for i, convo := range gc.conversations {
		menuNumber := i + 2
		if convo == gc.selectedConvo {
			menu += fmt.Sprintf(",%d", ansi.Colorf(menuNumber, ansi.Bold))
		} else if convo.Status().Unread {
			menu += fmt.Sprintf(",%d:%s", ansi.Colorf(menuNumber, ansi.Green, ansi.Bold), convo.peerUsername)
		} else {
			menu += fmt.Sprintf(",%d", menuNumber)
		}
	}

	var convoStatus *Status
	var roundLatency string
	if gc.selectedConvo != nil && gc.active[gc.selectedConvo] {
		convoStatus = gc.selectedConvo.Status()
		latency := fmt.Sprintf("%.1fs", convoStatus.Latency)
		if convoStatus.Latency == 0.0 {
			latency = "-"
		}
		round := fmt.Sprintf("%d", convoStatus.Round)
		if convoStatus.Round == 0 {
			round = "-"
		}
		var unacked string
		if convoStatus.Unacked > 0 {
			unacked = fmt.Sprintf("[%d unacked]", convoStatus.Unacked)
		}
		roundLatency = fmt.Sprintf("  [round: %s]  [latency: %s]  %s",
			round, latency, unacked)
	}

	// Indicate if the current window is scrolled up in the status bar.
	viewName := "main"
	if gc.selectedConvo != nil {
		viewName = gc.selectedConvo.ViewName()
	}
	focusedView, err := g.View(viewName)
	if err != nil {
		return err
	}
	more := ""
	if !focusedView.Autoscroll {
		more = "-MORE-"
	}

	fmt.Fprintf(sv, " [%s]  [%s]%s %s", gc.myName, menu, roundLatency, ansi.Colorf(more, ansi.Yellow, ansi.Bold))

	partner := "vuvuzela"
	if gc.selectedConvo != nil {
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

	if gc.selectedConvo == nil {
		pv.FgColor = gocui.ColorDefault
	} else {
		if gc.active[gc.selectedConvo] {
			pv.FgColor = gocui.ColorYellow
			if convoStatus.PeerResponding {
				pv.FgColor = gocui.ColorGreen
			}
		} else {
			pv.FgColor = gocui.ColorRed
		}
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

	if gc.selectedConvo != nil {
		return gc.setViewOnTop(gc.selectedConvo.ViewName())
	}
	return gc.setViewOnTop("main")
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

type launchStatus struct {
	isNewAlpenhornClient bool
	isNewVuvuzelaClient  bool
}

func (gc *GuiClient) Run(status launchStatus) {
	gui, err := gocui.NewGui(gocui.Output256)
	if err != nil {
		panic(err)
	}
	defer gui.Close()
	gc.gui = gui

	gui.SetManagerFunc(gc.layout)

	if err := gui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		panic(err)
	}
	for i, ch := range []rune{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'} {
		i := i
		err := gui.SetKeybinding("", ch, gocui.ModAlt, func(g *gocui.Gui, v *gocui.View) error {
			return gc.focusConvoIndex(i)
		})
		if err != nil {
			panic(err)
		}
	}
	if err := gui.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, gc.readLine); err != nil {
		panic(err)
	}
	if err := gui.SetKeybinding("input", gocui.KeyTab, gocui.ModNone, gc.tabComplete); err != nil {
		panic(err)
	}
	if err := gui.SetKeybinding("", gocui.KeyPgup, gocui.ModNone, gc.scrollUp); err != nil {
		panic(err)
	}
	if err := gui.SetKeybinding("", gocui.KeyPgdn, gocui.ModNone, gc.scrollDown); err != nil {
		panic(err)
	}

	gui.Cursor = true
	gui.BgColor = gocui.ColorDefault
	gui.FgColor = gocui.ColorDefault

	go func() {
		gc.Printf("Welcome to Vuvuzela. Type /help for help.\n")
		if status.isNewAlpenhornClient || status.isNewVuvuzelaClient {
			time.Sleep(500 * time.Millisecond)
			if status.isNewAlpenhornClient {
				gc.PrintfSync("\n-!- Generated new Alpenhorn client\n")
				gc.PrintfSync(" ·  Username:   %s\n", gc.alpenhornClient.Username)
				gc.PrintfSync(" ·  Public Key: %s\n", base32.EncodeToString(gc.alpenhornClient.LongTermPublicKey))
				gc.PrintfSync(" ·  Data Path:  %s\n", gc.alpenhornClient.ClientPersistPath)
			}
			if status.isNewVuvuzelaClient {
				gc.PrintfSync("\n-!- Generated new Vuvuzela client\n")
				gc.PrintfSync(" ·  Data Path:  %s\n", gc.convoClient.PersistPath)
			}
			gc.PrintfSync("\n@@@ Cautious users should verify the initial configs at the above paths before sending messages. @@@\n\n")
		}
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

	gc.WarnfSync("%s", buf.Bytes())
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
	case key == gocui.KeyHome:
		v.SetCursor(0, 0)
	case key == gocui.KeyEnd:
		line, _ := v.Line(0)
		v.SetCursor(len(line), 0)
	}
	// User typed something; don't send notifications.
	resetNotifyTimer()
}
