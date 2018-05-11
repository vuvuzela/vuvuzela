// Copyright 2015 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/jroimartin/gocui"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/log/ansi"
)

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

	"connect": {
		Help: "/connect connects to the Vuvuzela servers.",
		Handler: func(gc *GuiClient, args []string) error {
			// Connect needs to be called in a different goroutine since it
			// the calls PrintfSync functions.
			go gc.Connect()
			return nil
		},
	},

	"register": {
		Help: "/register <token> registers your username with the Alpenhorn servers.",
		Handler: func(gc *GuiClient, args []string) error {
			if len(args) == 0 {
				gc.Warnf("Usage: /register <token>\nSee https://vuvuzela.io to get started.\n")
				return nil
			}
			gc.Warnf("Checking registration status (this may take a minute)...\n")
			// Don't block the GUI while contacting the PKG servers.
			go gc.RegisterAll(args[0])
			return nil
		},
	},

	"w": {
		Help: "/w (<username>|<number>) creates or jumps to a window.",
		Handler: func(gc *GuiClient, args []string) error {
			if len(args) == 0 {
				gc.Warnf("Missing username or window number\n")
				return nil
			}

			winNum, err := strconv.ParseInt(args[0], 10, 0)
			if err == nil {
				if winNum < 0 {
					return nil
				}
				return gc.focusConvoIndex(int(winNum) - 1)
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
			convo.Warnf("Queued call: %s\n", convo.peerUsername)

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

			convo.Lock()
			pendingCall := convo.pendingCall
			convo.Unlock()
			if pendingCall == nil {
				convo.Warnf("No pending call.\n")
				return nil
			}
			if gc.activateConvo(convo, pendingCall) {
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


	"cancelfriend": {
	  Help: "/cancelfriend <username> cancle a sepcific friend request",
	  Handler: func(gc *GuiClient, args []string) error {
	    if len(args) == 0 {
	      gc.Warnf("Missing username\n")
	      return nil
	    }
	    username := args[0]
	    reqs := gc.alpenhornClient.GetOutgoingFriendRequests()
	    for _, req := range reqs {
	      if req.Username == username {
	        err := req.Cancel()
	        if err != nil {
	          gc.Warnf("%s for cancelling friend request %s\n", err, username);
	          return nil
	        }
	      }
	    }

	    gc.Warnf("No queued friend request sent to %s\n", username)
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
	gc.Printf("%s\nCommands:\n", ansi.Colorf("Vuvuzela Help", ansi.Bold))
	for _, cmd := range validCmds {
		gc.Printf("  %s\n", allCommands[cmd].Help)
	}
	gc.Printf("To jump between windows use the /w command, Alt-[1..9], or Esc+[1..9].\n")
	gc.Printf("Scroll up and down with PageUp and PageDown.\n")
	gc.Printf("Get started at: https://vuvuzela.io/getstarted\n")
	gc.Printf("Report bugs to: https://github.com/vuvuzela/vuvuzela\n")
	return nil
}

func (gc *GuiClient) tabComplete(_ *gocui.Gui, v *gocui.View) error {
	line := strings.TrimRight(v.Buffer(), "\n")
	if line == "" {
		return nil
	}
	if line[0] != '/' {
		return nil
	}

	args := strings.Split(line[1:], " ")

	var uniqChoices []string
	if len(args) == 1 {
		for cmd, _ := range commands {
			uniqChoices = append(uniqChoices, cmd)
		}
	} else {
		cmd := args[0]
		var choices []string
		switch cmd {
		case "w":
			gc.mu.Lock()
			for _, convo := range gc.conversations {
				choices = append(choices, convo.peerUsername)
			}
			gc.mu.Unlock()
		}
		switch cmd {
		case "call", "delfriend", "debugfriend", "addfriend", "w":
			for _, friend := range gc.alpenhornClient.GetFriends() {
				choices = append(choices, friend.Username)
			}
		}
		switch cmd {
		case "approve":
			for _, req := range gc.alpenhornClient.GetIncomingFriendRequests() {
				choices = append(choices, req.Username)
			}
		}

		if len(choices) == 0 {
			return nil
		}

		// remove dupes
		seen := make(map[string]bool)
		for _, choice := range choices {
			if !seen[choice] {
				uniqChoices = append(uniqChoices, choice)
				seen[choice] = true
			}
		}
	}

	prefix := args[len(args)-1]
	matches := completePrefix(prefix, uniqChoices)
	if len(matches) == 0 {
		return nil
	}
	if len(matches) > 1 {
		sort.Strings(matches)
		gc.Warnf("Choices: %v\n", matches)
		return nil
	}
	match := matches[0]
	completion := match[len(prefix):]

	fmt.Fprintf(v, "%s ", completion)
	v.MoveCursor(len(completion)+1, 0, true)
	return nil
}

func completePrefix(prefix string, choices []string) []string {
	matches := make([]string, 0)
	for _, choice := range choices {
		if strings.HasPrefix(choice, prefix) {
			matches = append(matches, choice)
		}
	}
	return matches
}
