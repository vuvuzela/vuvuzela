package internal

import (
	"encoding/json"
	"os"

	log "github.com/Sirupsen/logrus"
)

func ReadJSONFile(path string, val interface{}) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(val); err != nil {
		log.Fatalf("json decoding error: %s", err)
	}
}
