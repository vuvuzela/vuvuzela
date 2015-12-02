package vuvuzela

import (
	"testing"
)

func TestDialExchangeMarshal(t *testing.T) {
	ex := new(DialExchange)
	_ = ex.Marshal()
}
