package internal

import (
	"bytes"
	"fmt"
)

type ansiCode int

const (
	ansiReset   ansiCode = 0
	ansiReverse          = 7
	red                  = 31
	green                = 32
	yellow               = 33
	blue                 = 34
	magenta              = 35
	cyan                 = 36
)

var allColors = []ansiCode{red, green, yellow, blue, magenta, cyan}

type ansiFormatter struct {
	value interface{}
	codes []ansiCode
}

func color(value interface{}, codes ...ansiCode) interface{} {
	if len(codes) == 0 {
		return value
	}
	return &ansiFormatter{value, codes}
}

func (af *ansiFormatter) Format(f fmt.State, c rune) {
	// reconstruct the format string in bf
	bf := new(bytes.Buffer)
	bf.WriteByte('%')
	for _, x := range []byte{'-', '+', '#', ' ', '0'} {
		if f.Flag(int(x)) {
			bf.WriteByte(x)
		}
	}
	if w, ok := f.Width(); ok {
		fmt.Fprint(bf, w)
	}
	if p, ok := f.Precision(); ok {
		fmt.Fprintf(bf, ".%d", p)
	}
	bf.WriteRune(c)
	format := bf.String()

	if len(af.codes) == 0 {
		fmt.Fprintf(f, format, af.value)
		return
	}

	fmt.Fprintf(f, "\x1b[%d", af.codes[0])
	for _, code := range af.codes[1:] {
		fmt.Fprintf(f, ";%d", code)
	}
	f.Write([]byte{'m'})
	fmt.Fprintf(f, format, af.value)
	fmt.Fprint(f, "\x1b[0m")
}
