// parallelfor.go by Jelle van den Hooff
package internal

import (
	"runtime"
	"sync"
	"sync/atomic"
)

type GP struct {
	max, current, step int64
	wg                 sync.WaitGroup
}

func (gp *GP) Next() (int64, bool) {
	base := atomic.AddInt64(&gp.current, gp.step) - gp.step

	if base >= gp.max {
		return 0, false
	} else {
		return base, true
	}
}

type P struct {
	gp           *GP
	max, current int64
}

func (p *P) Next() (int, bool) {
	if p.current >= p.max {
		r, ok := p.gp.Next()
		if !ok {
			return 0, false
		}
		p.current, p.max = r, r+p.gp.step
		if p.max > p.gp.max {
			p.max = p.gp.max
		}
	}

	r := p.current
	p.current += 1

	return int(r), true
}

func ParallelFor(n int, f func(p *P)) {
	// TODO: this formula could probably be more clever
	step := n / runtime.NumCPU() / 100
	if step < 10 {
		step = 10
	}

	gp := &GP{
		max:     int64(n),
		current: 0,
		step:    int64(step),
	}

	gp.wg.Add(runtime.NumCPU())

	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			p := &P{
				gp: gp,
			}
			f(p)
			gp.wg.Done()
		}()
	}

	gp.wg.Wait()
}
