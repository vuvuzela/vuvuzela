package vuvuzela

import (
	"time"
)

const (
	SizeMessage = 240

	// Eventually this might be dynamic, but one bucket is usually
	// sufficient if users don't dial very often.
	TotalDialBuckets = 1

	DialWait           = 10 * time.Second
	DefaultReceiveWait = 5 * time.Second

	DefaultServerAddr = ":2718"
	DefaultServerPort = "2718"
)
