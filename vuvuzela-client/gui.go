package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/davidlazar/gocui"

	. "vuvuzela.io/vuvuzela"
	. "vuvuzela.io/vuvuzela/internal"
)

type GuiClient struct {
	sync.Mutex

	pki    *PKI
	myName string

	gui    *gocui.Gui
	client *Client

	selectedConvo *Conversation
	conversations map[string]*Conversation
}

func (gc *GuiClient) switchConversation(peer string) {
	var convo *Conversation

	convo, ok := gc.conversations[peer]
	if !ok {
		convo = &Conversation{
			pki:          gc.pki,
			myUsername:   gc.myName,
			peerUsername: peer,
			gui:          gc,
		}
		// TODO we need the secret key from Alpenhorn
		convo.Init()
		gc.conversations[peer] = convo
	}

	gc.selectedConvo = convo
	gc.activateConvo(convo)
	gc.Warnf("Now talking to %s\n", peer)
}

func (gc *GuiClient) activateConvo(convo *Conversation) {
	if gc.client != nil {
		convo.Lock()
		convo.lastPeerResponding = false
		convo.lastLatency = 0
		convo.Unlock()
		gc.client.SetConvoHandler(convo)
	}
}

func (gc *GuiClient) handleLine(line string) error {
	switch {
	case line == "/quit":
		return gocui.Quit
	case strings.HasPrefix(line, "/talk "):
		peer := line[6:]
		gc.switchConversation(peer)
	default:
		msg := strings.TrimSpace(line)
		gc.selectedConvo.QueueTextMessage([]byte(msg))
		gc.Printf("<%s> %s\n", gc.myName, msg)
	}
	return nil
}

func (gc *GuiClient) readLine(_ *gocui.Gui, v *gocui.View) error {
	// HACK: pressing enter on startup causes panic
	if len(v.Buffer()) == 0 {
		return nil
	}
	_, cy := v.Cursor()
	line, err := v.Line(cy - 1)
	if err != nil {
		return err
	}
	if line == "" {
		return nil
	}
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

func (gc *GuiClient) Connect() error {
	if gc.client == nil {
		gc.client = NewClient(gc.pki.EntryServer)
	}
	gc.activateConvo(gc.selectedConvo)
	return gc.client.Connect()
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
	gui.ShowCursor = true
	gui.BgColor = gocui.ColorDefault
	gui.FgColor = gocui.ColorDefault
	gui.SetLayout(gc.layout)

	gc.conversations = make(map[string]*Conversation)
	gc.switchConversation(gc.myName)

	go func() {
		time.Sleep(500 * time.Millisecond)
		if err := gc.Connect(); err != nil {
			gc.Warnf("Failed to connect: %s\n", err)
		}
		gc.Warnf("Connected: %s\n", gc.pki.EntryServer)
	}()

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
