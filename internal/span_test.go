package internal

import (
	"testing"
)

func TestSpans(t *testing.T) {
	testEqual(t, Spans(0, 4000), nil)
	testEqual(t, Spans(1, 4000), []Span{{0, 1}})
	testEqual(t, Spans(4000, 4000), []Span{{0, 4000}})
	testEqual(t, Spans(4001, 4000), []Span{{0, 4000}, {4000, 1}})
	testEqual(t, Spans(8000, 4000), []Span{{0, 4000}, {4000, 4000}})
}

func testEqual(t *testing.T, actual, expected []Span) {
	if !equal(actual, expected) {
		t.Fatalf("expecting %v, got %v", expected, actual)
	}
}

func equal(a, b []Span) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
