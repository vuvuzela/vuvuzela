// Types used by the entry server and client
package vuvuzela

import (
	"encoding/json"
	"fmt"
)

//go:generate stringer -type=MsgType
type MsgType uint8

const (
	// from client to server
	MsgConvoRequest MsgType = iota
	MsgDialRequest

	// from server to client
	MsgBadRequestError
	MsgConvoError
	MsgConvoResponse
	MsgDialError
	MsgDialBucket
	MsgAnnounceConvoRound
	MsgAnnounceDialRound
)

type Envelope struct {
	Type    MsgType
	Message json.RawMessage
}

func (e *Envelope) Open() (interface{}, error) {
	var v interface{}
	switch e.Type {
	case MsgConvoRequest:
		v = new(ConvoRequest)
	case MsgDialRequest:
		v = new(DialRequest)
	case MsgBadRequestError:
		v = new(BadRequestError)
	case MsgConvoError:
		v = new(ConvoError)
	case MsgConvoResponse:
		v = new(ConvoResponse)
	case MsgDialBucket:
		v = new(DialBucket)
	case MsgAnnounceConvoRound:
		v = new(AnnounceConvoRound)
	case MsgAnnounceDialRound:
		v = new(AnnounceDialRound)
	default:
		return nil, fmt.Errorf("unknown message type: %d", e.Type)
	}
	if err := json.Unmarshal(e.Message, v); err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %s", err)
	}
	return v, nil
}

func Envelop(v interface{}) (*Envelope, error) {
	var t MsgType
	switch v.(type) {
	case *ConvoRequest:
		t = MsgConvoRequest
	case *DialRequest:
		t = MsgDialRequest
	case *BadRequestError:
		t = MsgBadRequestError
	case *ConvoError:
		t = MsgConvoError
	case *ConvoResponse:
		t = MsgConvoResponse
	case *DialError:
		t = MsgDialError
	case *DialBucket:
		t = MsgDialBucket
	case *AnnounceConvoRound:
		t = MsgAnnounceConvoRound
	case *AnnounceDialRound:
		t = MsgAnnounceDialRound
	default:
		return nil, fmt.Errorf("unsupported message type: %T", v)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %s", err)
	}
	return &Envelope{
		Type:    t,
		Message: data,
	}, nil
}

type ConvoRequest struct {
	Round uint32
	Onion []byte
}

type DialRequest struct {
	Round uint32
	Onion []byte
}

type BadRequestError struct {
	Err string
}

func (e *BadRequestError) Error() string {
	return e.Err
}

type ConvoError struct {
	Round uint32
	Err   string
}

func (e *ConvoError) Error() string {
	return fmt.Sprintf("round c%d: %s", e.Round, e.Err)
}

type ConvoResponse struct {
	Round uint32
	Onion []byte
}

type DialError struct {
	Round uint32
	Err   string
}

func (e *DialError) Error() string {
	return fmt.Sprintf("round d%d: %s", e.Round, e.Err)
}

type DialBucket struct {
	Round  uint32
	Intros [][SizeEncryptedIntro]byte
}

type AnnounceConvoRound struct {
	Round uint32
}

type AnnounceDialRound struct {
	Round   uint32
	Buckets uint32
}
