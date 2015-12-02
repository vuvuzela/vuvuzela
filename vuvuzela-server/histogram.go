package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"gopkg.in/gizak/termui.v1"

	"github.com/davidlazar/vuvuzela"
)

type Histogram struct {
	Mu         float64
	NumServers int

	singles []int
	doubles []int

	normalizedSingles []int
	normalizedDoubles []int

	spSingles *termui.Sparklines
	spDoubles *termui.Sparklines
}

func (h *Histogram) resize() {
	tw := termui.TermWidth() - 4
	h.spSingles.Width = tw
	h.spDoubles.Width = tw

	th := termui.TermHeight()/2 - 1
	h.spSingles.Height = th
	h.spDoubles.Height = th
	if th > 3 {
		h.spSingles.Lines[0].Height = th - 3
		h.spDoubles.Lines[0].Height = th - 3
	} else {
		h.spSingles.Lines[0].Height = 1
		h.spDoubles.Lines[0].Height = 1
	}

	h.spDoubles.Y = th + 2

	termui.Body.Width = termui.TermWidth()
	termui.Body.Align()
	h.render()
}

// Shift the distribution so the user can more clearly see the variation
// in noise across rounds.
func (h *Histogram) render() {
	singleShift := (h.NumServers-1)*int(h.Mu) - h.spSingles.Height - 32
	doubleShift := (h.NumServers-1)*int(h.Mu/2) - h.spDoubles.Height - 16

	for i := range h.singles {
		if s := h.singles[i]; s == 0 {
			h.normalizedSingles[i] = 0
		} else if n := s - singleShift; n > 2 {
			h.normalizedSingles[i] = n
		} else {
			// to prevent confusion, don't let the sparkline go to 0
			h.normalizedSingles[i] = 2
		}

		if s := h.doubles[i]; s == 0 {
			h.normalizedDoubles[i] = 0
		} else if n := s - doubleShift; n > 2 {
			h.normalizedDoubles[i] = n
		} else {
			h.normalizedDoubles[i] = 2
		}
	}

	h.spSingles.Lines[0].Data = h.normalizedSingles
	h.spDoubles.Lines[0].Data = h.normalizedDoubles
	termui.Render(h.spSingles, h.spDoubles)
}

func (h *Histogram) run(accessCounts chan *vuvuzela.AccessCount) {
	h.singles = make([]int, 512)
	h.doubles = make([]int, 512)
	h.normalizedSingles = make([]int, 512)
	h.normalizedDoubles = make([]int, 512)

	// log will corrupt display, so only log errors
	log.SetLevel(log.ErrorLevel)

	err := termui.Init()
	if err != nil {
		panic(err)
	}
	defer termui.Close()

	termui.UseTheme("helloworld")
	th := termui.Theme()
	th.BodyBg = termui.ColorDefault
	th.BlockBg = termui.ColorDefault
	th.BorderBg = termui.ColorDefault
	th.BorderLabelTextBg = termui.ColorDefault
	termui.SetTheme(th)

	spSingles := termui.NewSparkline()
	spSingles.Data = h.singles
	spSingles.LineColor = termui.ColorBlue

	spDoubles := termui.NewSparkline()
	spDoubles.Data = h.doubles
	spDoubles.LineColor = termui.ColorMagenta

	h.spSingles = termui.NewSparklines(spSingles)
	h.spSingles.X = 2
	h.spSingles.Y = 1
	h.spSingles.Border.Label = "Idle Users"

	h.spDoubles = termui.NewSparklines(spDoubles)
	h.spDoubles.X = 2
	h.spDoubles.Border.Label = "Active Users"

	h.resize()

	for {
		select {
		case e := <-termui.EventCh():
			if e.Type == termui.EventKey && e.Ch == 'q' {
				log.SetLevel(log.InfoLevel)
				return
			}
			if e.Type == termui.EventKey && e.Key == termui.KeyCtrlC {
				termui.Close()
				os.Exit(1)
			}
			if e.Type == termui.EventResize {
				h.resize()
			}
		case a := <-accessCounts:
			h.singles = append(h.singles[1:], int(a.Singles))
			h.doubles = append(h.doubles[1:], int(a.Doubles))
			//log.Errorf("%#v", a)
			h.render()
		}
	}
}
