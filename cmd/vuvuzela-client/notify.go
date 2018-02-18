// Copyright 2018 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	"github.com/gen2brain/beeep"
)

func notify(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	beeep.Notify("Vuvuzela", msg, "")
}

var notifyChan = make(chan string, 1)
var notifyResetChan = make(chan struct{}, 1)

func resetNotifyTimer() {
	select {
	case notifyResetChan <- struct{}{}:
	default:
	}
}

func seldomNotify(format string, args ...interface{}) {
	select {
	case notifyChan <- fmt.Sprintf(format, args...):
	default:
	}
}

func init() {
	go seldomNotifyLoop()
}

func seldomNotifyLoop() {
	duration := 4 * time.Minute
	timer := time.NewTimer(duration)
	for {
		select {
		case <-notifyResetChan:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(duration)
		case msg := <-notifyChan:
			select {
			case <-timer.C:
				beeep.Notify("Vuvuzela", msg, "")
				timer.Reset(duration)
			default:
			}
		}
	}
}
