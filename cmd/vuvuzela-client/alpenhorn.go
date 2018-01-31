package main

import (
	"regexp"

	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/log"
)

func (gc *GuiClient) Error(err error) {
	if *debug {
		log.Error(err)
		return
	}
	// Ignore some errors by default and do it the hacky way since
	// we don't have a great plan for errors anyway.
	matched, _ := regexp.MatchString("round [0-9]+ not configured", err.Error())
	if matched {
		return
	}
	log.Error(err)
}

func (gc *GuiClient) ConfirmedFriend(f *alpenhorn.Friend) {
	gc.WarnfSync("Confirmed friend: %s\n", f.Username)
}

func (gc *GuiClient) SentFriendRequest(r *alpenhorn.OutgoingFriendRequest) {
	gc.WarnfSync("Sent friend request: %s\n", r.Username)
}

func (gc *GuiClient) ReceivedFriendRequest(r *alpenhorn.IncomingFriendRequest) {
	gc.WarnfSync("Received friend request: %s\n", r.Username)
	gc.WarnfSync("Type `/approve %s` to approve the friend request.\n", r.Username)
}

func (gc *GuiClient) UnexpectedSigningKey(in *alpenhorn.IncomingFriendRequest, out *alpenhorn.OutgoingFriendRequest) {
	gc.WarnfSync("Unexpected signing key: %s\n", in.Username)
}

func (gc *GuiClient) SendingCall(call *alpenhorn.OutgoingCall) {
	convo := gc.getOrCreateConvo(call.Username)
	convo.WarnfSync("Calling %s ...\n", call.Username)
	round := gc.latestConvoRound()
	epochStart, intent := stdRoundSyncer.outgoingCallConvoRound(round)

	call.UpdateIntent(intent)

	wheel := &keywheelStart{
		sessionKey: call.SessionKey(),
		convoRound: epochStart,
	}
	if !gc.activateConvo(convo, wheel) {
		convo.Lock()
		convo.pendingCall = wheel
		convo.Unlock()
		convo.WarnfSync("Too many active conversations! Hang up another convo and type /answer to answer the call.\n")
	}
}

func (gc *GuiClient) ReceivedCall(call *alpenhorn.IncomingCall) {
	convo := gc.getOrCreateConvo(call.Username)
	convo.WarnfSync("Received call: %s\n", call.Username)

	round := gc.latestConvoRound()
	wheel := &keywheelStart{
		sessionKey: call.SessionKey,
		convoRound: stdRoundSyncer.incomingCallConvoRound(round, call.Intent),
	}
	if !gc.activateConvo(convo, wheel) {
		convo.Lock()
		convo.pendingCall = wheel
		convo.Unlock()
		convo.WarnfSync("Too many active conversations! Hang up another convo and type /answer to answer the call.\n")
	}
}

func (gc *GuiClient) NewConfig(chain []*config.SignedConfig) {
	// TODO we should let the user know the differences between versions
	prev := chain[len(chain)-1]
	next := chain[0]
	gc.WarnfSync("New %q config: %s -> %s\n", prev.Service, prev.Hash(), next.Hash())
}
