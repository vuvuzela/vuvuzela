package vzlog

import (
	"fmt"
	"os"

	"vuvuzela.io/alpenhorn/log"
)

type ProductionOutput struct {
	dirHandler    *log.OutputDir
	stderrHandler log.EntryHandler
}

func NewProductionOutput(logsDir string) (ProductionOutput, error) {
	h := ProductionOutput{
		stderrHandler: &log.OutputText{Out: log.Stderr},
	}

	if logsDir != "" {
		err := os.MkdirAll(logsDir, 0770)
		if err != nil {
			return h, fmt.Errorf("failed to create logs directory: %s", err)
		}

		h.dirHandler = &log.OutputDir{
			Dir: logsDir,
		}
	}

	return h, nil
}

func (h ProductionOutput) Name() string {
	if h.dirHandler == nil {
		return "[stderr]"
	}
	return h.dirHandler.Dir
}

func (h ProductionOutput) Fire(e *log.Entry) {
	if h.dirHandler != nil {
		h.dirHandler.Fire(e)

		// Only print errors to stderr.
		if e.Level > log.ErrorLevel {
			return
		}
	}
	h.stderrHandler.Fire(e)
}
