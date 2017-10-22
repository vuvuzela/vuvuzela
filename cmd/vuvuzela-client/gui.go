package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
	gc.mu.Unlock()

	for i, convo := range st.activeConvos {
		convo.Reply(round, replies[i])
	}
}

func (gc *GuiClient) activateConvo(convo *Conversation, key *[32]byte) bool {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if len(gc.active) < NumOutgoing {
		gc.active[convo] = true
		convo.Lock()
		convo.secretKey = key
		convo.lastPeerResponding = false
		convo.lastLatency = 0
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

type Command struct {
	Help    string
	Handler func(gc *GuiClient, args []string) error
}

var commands = map[string]Command{
	"help": {
		Help: "/help prints this help message.",
		Handler: func(gc *GuiClient, _ []string) error {
			return gc.printHelp()
		},
	},

	"quit": {
		Help: "/quit quits vuvuzela.",
		Handler: func(_ *GuiClient, _ []string) error {
			return gocui.ErrQuit
		},
	},

	"w": {
		Help: "/w <username> goes to the convo window for the given username.",
		Handler: func(gc *GuiClient, args []string) error {
			if len(args) == 0 {
				gc.Warnf("Missing username\n")
				return nil
			}

			username := args[0]
			convo := gc.getOrCreateConvo(username)
			return gc.focusConvo(convo)
		},
	},

	"wc": {
		Help: "/wc closes the current window.",
		Handler: func(gc *GuiClient, args []string) error {
			gc.mu.Lock()
			convo := gc.selectedConvo
			gc.mu.Unlock()
			if convo == nil {
				gc.Warnf("You can't close the main window!\n")
				return nil
			}

			gc.deactivateConvo(convo)

			gc.mu.Lock()
			index := -1
			for i, c := range gc.conversations {
				if c == convo {
					index = i
				}
			}
			// delete element from list (slice tricks)
			copy(gc.conversations[index:], gc.conversations[index+1:])
			gc.conversations[len(gc.conversations)-1] = nil
			gc.conversations = gc.conversations[:len(gc.conversations)-1]
			gc.mu.Unlock()

			// TODO focus the previous window instead
			return gc.focusMain()
		},
	},

	"list": {
		Help: "/list prints your friends list and friend requests.",
		Handler: func(gc *GuiClient, _ []string) error {
			buf := new(bytes.Buffer)

			inReqs := gc.alpenhornClient.GetIncomingFriendRequests()
			if len(inReqs) > 0 {
				fmt.Fprintf(buf, "%s\n", ansi.Colorf("Incoming Friend Requests", ansi.Bold))
				tw := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
				for _, req := range inReqs {
					key := base32.EncodeToString(req.LongTermKey)
					fmt.Fprintf(tw, "  %s\t{%s}\n", req.Username, key)
				}
				tw.Flush()
			}

			prettyPrintOutReqs := func(reqs []*alpenhorn.OutgoingFriendRequest) {
				tw := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
				for _, req := range reqs {
					confirm := ""
					if req.Confirmation {
						confirm = "(confirmation)"
					}
					key := "(no key specified)"
					if req.ExpectedKey != nil {
						key = "{" + base32.EncodeToString(req.ExpectedKey) + "}"
					}
					fmt.Fprintf(tw, "  %s\t%s\t%s\n", req.Username, key, confirm)
				}
				tw.Flush()
			}

			outReqs := gc.alpenhornClient.GetOutgoingFriendRequests()
			if len(outReqs) > 0 {
				fmt.Fprintf(buf, "%s\n", ansi.Colorf("Outgoing Friend Requests", ansi.Bold))
				prettyPrintOutReqs(outReqs)
			}

			sentReqs := gc.alpenhornClient.GetSentFriendRequests()
			if len(sentReqs) > 0 {
				fmt.Fprintf(buf, "%s\n", ansi.Colorf("Sent Friend Requests", ansi.Bold))
				prettyPrintOutReqs(sentReqs)
			}

			friends := gc.alpenhornClient.GetFriends()
			fmt.Fprintf(buf, "%s\n", ansi.Colorf("Friends", ansi.Bold))
			if len(friends) == 0 {
				fmt.Fprintf(buf, "  No friends; use /addfriend to add a friend\n")
			} else {
				tw := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
				for _, friend := range friends {
					fmt.Fprintf(tw, "  %s\n", friend.Username)
				}
				tw.Flush()
			}
			fmt.Fprintf(buf, "\n")

			gc.Printf("%s", buf.String())

			return nil
		},
	},

	"debugfriend": {
		Help: "/debugfriend <username> prints a friend's keywheel state.",
		Handler: func(gc *GuiClient, args []string) error {
			if len(args) == 0 {
				gc.Warnf("Missing username\n")
				return nil
			}
			username := args[0]
			friend := gc.alpenhornClient.GetFriend(username)
			if friend == nil {
				gc.Warnf("%q is not in your friends list!\n")
				return nil
			}

			keyRound, _ := friend.UnsafeKeywheelState()
			keyRound = (keyRound + 100) / 100 * 100
			key := sha256.Sum256(friend.SessionKey(keyRound)[:])
			keyStr := base64.RawURLEncoding.EncodeToString(key[:])[:12]
			gc.Warnf("Keywheel for %q: {%d|%s...}\n", username, keyRound, keyStr)
			gc.Warnf("You and your friend should have the same keywheel for eachother.\n")

			return nil
		},
	},

	"call": {
		Help: "/call [<username>] calls a friend.",
		Handler: func(gc *GuiClient, args []string) error {
			gc.mu.Lock()
			convo := gc.selectedConvo
			gc.mu.Unlock()
			if len(args) == 0 && convo == nil {
				gc.Warnf("Try `/call <username>` or run /call in a conversation window.\n")
				return nil
			}

			if len(args) > 0 {
				convo = gc.getOrCreateConvo(args[0])
			}
			gc.focusConvo(convo)

			gc.mu.Lock()
			numActive := len(gc.active)
			gc.mu.Unlock()
			if numActive == NumOutgoing {
				convo.Warnf("Too many active conversations!\n")
				return nil
			}

			friend := gc.alpenhornClient.GetFriend(convo.peerUsername)
			if friend == nil {
				convo.Warnf("%q is not in your friends list! Try `/addfriend %s` first.\n", convo.peerUsername, convo.peerUsername)
				return nil
			}
			_ = friend.Call(0)
			convo.Warnf("Calling %s ...\n", convo.peerUsername)

			return nil
		},
	},

	"hangup": {
		Help: "/hangup hangs up the current conversation.",
		Handler: func(gc *GuiClient, args []string) error {
			gc.mu.Lock()
			convo := gc.selectedConvo
			gc.mu.Unlock()

			if convo == nil {
				gc.Warnf("/hangup only works in a conversation window.\n")
				return nil
			}

			if gc.deactivateConvo(convo) {
				convo.Warnf("Hung up!\n")
			} else {
				convo.Warnf("This conversation is not active!\n")
			}
			return nil
		},
	},

	"answer": {
		Help: "/answer answers a held call.",
		Handler: func(gc *GuiClient, args []string) error {
			gc.mu.Lock()
			convo := gc.selectedConvo
			gc.mu.Unlock()

			if convo == nil {
				gc.Warnf("/answer only works in a conversation window.\n")
				return nil
			}

			if convo.pendingCall == nil {
				convo.Warnf("No pending call.\n")
				return nil
			}
			var sessionKey *[32]byte
			switch call := convo.pendingCall.(type) {
			case *alpenhorn.IncomingCall:
				sessionKey = call.SessionKey
			case *alpenhorn.OutgoingCall:
				sessionKey = call.SessionKey()
			default:
				panic(fmt.Sprintf("unknown call type: %T", call))
			}
			if gc.activateConvo(convo, sessionKey) {
				convo.Lock()
				convo.pendingCall = nil
				convo.Unlock()
				convo.Warnf("Now talking to %q\n", convo.peerUsername)
			} else {
				convo.Warnf("Too many active conversations! Hang up another convo and try again.\n")
			}
			return nil
		},
	},

	"addfriend": {
		Help: "/addfriend <username> sends a friend request to a friend.",
		Handler: func(gc *GuiClient, args []string) error {
			if len(args) == 0 {
				gc.Warnf("Missing username\n")
				return nil
			}

			username := args[0]
			_, err := gc.alpenhornClient.SendFriendRequest(username, nil)
			if err != nil {
				gc.Warnf("Error sending friend request: %s", err)
				return nil
			}
			gc.Warnf("Queued friend request: %s\n", username)
			return nil
		},
	},

	"delfriend": {
		Help: "/delfriend <username> removes a friend from your friends list.",
		Handler: func(gc *GuiClient, args []string) error {
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
	},

	"approve": {
		Help: "/approve <username> approves a friend request.",
		Handler: func(gc *GuiClient, args []string) error {
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
	},
}

// avoid initialization loop
var allCommands map[string]Command

func init() {
	allCommands = commands
}

func (gc *GuiClient) printHelp() error {
	validCmds := make([]string, 0)
	for cmd := range allCommands {
		validCmds = append(validCmds, cmd)
	}
	sort.Strings(validCmds)
	gc.Warnf("Valid commands:\n")
	for _, cmd := range validCmds {
		gc.Warnf("  %s\n", allCommands[cmd].Help)
	}
	gc.Warnf("Report bugs to: https://github.com/vuvuzela/vuvuzela\n")
	return nil
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

func (gc *GuiClient) Warnf(format string, v ...interface{}) {
	gc.Printf("-!- "+format, v...)
}

func (gc *GuiClient) WarnfSync(format string, v ...interface{}) {
	gc.PrintfSync("-!- "+format, v...)
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
		sv.BgColor = gocui.ColorBlue
		sv.FgColor = gocui.ColorWhite
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
		roundLatency = fmt.Sprintf("  [round: %s]  [latency: %s]  ", round, latency)
	}

	fmt.Fprintf(sv, " [%s]  [%s]%s", gc.myName, menu, roundLatency)

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

func (gc *GuiClient) Connect() {
	gc.Register()

	if err := gc.alpenhornClient.Connect(); err != nil {
		gc.WarnfSync("Failed to connect to alpenhorn service: %s\n", err)
	} else {
		gc.WarnfSync("Connected to alpenhorn service.\n")
	}

	if err := gc.convoClient.Connect(); err != nil {
		gc.WarnfSync("Failed to connect to convo service: %s\n", err)
	} else {
		gc.WarnfSync("Connected to convo service.\n")
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
				gc.WarnfSync("Failed to register with PKG %s: %s\n", st.Server.Address, err)
				continue
			}
			gc.WarnfSync("Registered %q with PKG %s\n", gc.alpenhornClient.Username, st.Server.Address)
		} else {
			gc.WarnfSync("Failed to check account status with PKG %s: %s\n", st.Server.Address, st.Error)
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
	gui.Cursor = true
	gui.BgColor = gocui.ColorDefault
	gui.FgColor = gocui.ColorDefault

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
	}
}
