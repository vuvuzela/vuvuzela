package internal

import (
	"bytes"
	"fmt"

	log "github.com/Sirupsen/logrus"
)

type ServerFormatter struct{}

func (f *ServerFormatter) Format(entry *log.Entry) ([]byte, error) {
	buf := new(bytes.Buffer)

	ts := entry.Time.Format("15:04:05")

	var tsColor []ansiCode
	switch entry.Level {
	case log.ErrorLevel, log.FatalLevel, log.PanicLevel:
		tsColor = append(tsColor, red)
	}
	if bug, hasBug := entry.Data["bug"].(bool); bug && hasBug {
		tsColor = append(tsColor, ansiReverse)
	}

	fmt.Fprintf(buf, "%s | ", color(ts, tsColor...))

	service, _ := entry.Data["service"].(string)
	round, hasRound := entry.Data["round"].(uint32)
	rpc, hasRpc := entry.Data["rpc"].(string)
	call, hasCall := entry.Data["call"].(string)

	if hasRound {
		c := allColors[int(round)%len(allColors)]
		switch service {
		case "dial":
			fmt.Fprintf(buf, "%d ", color(round, c, ansiReverse))
		default:
			fmt.Fprintf(buf, "%d ", color(round, c))
		}
	}

	if hasRpc {
		fmt.Fprintf(buf, "%s ", rpc)
	}
	if hasCall {
		fmt.Fprintf(buf, "%s ", call)
	}
	if entry.Message != "" {
		fmt.Fprintf(buf, "%s ", entry.Message)
	}

	for _, k := range []string{"service", "round", "rpc", "call"} {
		delete(entry.Data, k)
	}

	if len(entry.Data) > 0 {
		fmt.Fprint(buf, "| ")
		writeMap(buf, entry.Data)
	}

	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

type GuiFormatter struct{}

// TODO gocui doesn't support color text:
// https://github.com/jroimartin/gocui/issues/9
func (f *GuiFormatter) Format(entry *log.Entry) ([]byte, error) {
	buf := new(bytes.Buffer)

	ts := entry.Time.Format("15:04:05")

	fmt.Fprintf(buf, "%s %s | ", ts, entry.Level.String())

	call, hasCall := entry.Data["call"].(string)
	if hasCall {
		fmt.Fprintf(buf, "%s ", call)
	}
	if entry.Message != "" {
		fmt.Fprintf(buf, "%s ", entry.Message)
	}

	for _, k := range []string{"call"} {
		delete(entry.Data, k)
	}

	if len(entry.Data) > 0 {
		fmt.Fprint(buf, "| ")
		writeMap(buf, entry.Data)
	}

	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func writeMap(buf *bytes.Buffer, m map[string]interface{}) {
	for k, v := range m {
		buf.WriteString(k)
		buf.WriteByte('=')
		switch v := v.(type) {
		case string, error:
			fmt.Fprintf(buf, "%q", v)
		default:
			fmt.Fprint(buf, v)
		}
		buf.WriteByte(' ')
	}
}
