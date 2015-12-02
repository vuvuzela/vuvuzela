// +build !amd64

package rand

// cpu returns a unique identifier for the core the current goroutine is
// executing on. This function is platform dependent, and is implemented in
// cpu_*.s.
func cpu() uint64 {
	// this reverts the behaviour to that of a regular DRWMutex
	return 0
}
