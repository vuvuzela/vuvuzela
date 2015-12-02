package internal

type Span struct {
	Start int
	Count int
}

func Spans(total, spanSize int) []Span {
	spans := make([]Span, 0, (total+spanSize-1)/spanSize)
	var c int
	for i := 0; i < total; i += c {
		if i+spanSize <= total {
			c = spanSize
		} else {
			c = total - i
		}
		spans = append(spans, Span{Start: i, Count: c})
	}
	return spans
}
