package main

import (
	"vuvuzela.io/alpenhorn"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/log"
)

func (gc *GuiClient) Error(err error) {
	log.Error(err)
}

func (gc *GuiClient) ConfirmedFriend(f *alpenhorn.Friend) {
	gc.Warnf("Confirmed friend: %s\n", f.Username)
}

func (gc *GuiClient) SentFriendRequest(r *alpenhorn.OutgoingFriendRequest) {
	gc.Warnf("Sent friend request: %s\n", r.Username)
}

func (gc *GuiClient) ReceivedFriendRequest(r *alpenhorn.IncomingFriendRequest) {
	gc.Warnf("Received friend request: %s\n", r.Username)
	gc.Warnf("Type `/approve %s` to approve the friend request.\n", r.Username)
}

func (gc *GuiClient) UnexpectedSigningKey(in *alpenhorn.IncomingFriendRequest, out *alpenhorn.OutgoingFriendRequest) {
	gc.Warnf("Unexpected signing key: %s\n", in.Username)
}

func (gc *GuiClient) SentCall(call *alpenhorn.OutgoingCall) {
	gc.Warnf("Sent call: %s\n", call.Username)
	gc.switchConversation(call.Username, call.SessionKey())
}

func (gc *GuiClient) ReceivedCall(call *alpenhorn.IncomingCall) {
	gc.Warnf("Received call: %s\n", call.Username)
	gc.switchConversation(call.Username, call.SessionKey)
}

func (gc *GuiClient) NewConfig(chain []*config.SignedConfig) {
	// TODO we should let the user know the differences between versions
	prev := chain[len(chain)-1]
	next := chain[0]
	gc.Warnf("New %q config: %s -> %s\n", prev.Service, prev.Hash(), next.Hash())
}
