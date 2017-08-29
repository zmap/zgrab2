package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/ajholland/zflags"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	_ "github.com/zmap/zgrab2/zmodules"
)

func main() {
	if _, err := zgrab2.ParseFlags(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok {
			// If flag parsed and flag is Help type, exit 0
			if flagsErr.Type == flags.ErrHelp {
				os.Exit(0)
			} else {
				log.Fatal(err.Error())
			}
		} else {
			log.Fatal(err.Error())
		}
	}
	m := zgrab2.MakeMonitor()
	start := time.Now()
	log.Infof("started grab at %s", start.Format(time.RFC3339))
	zgrab2.Process(m)
	end := time.Now()
	log.Infof("finished grab at %s", end.Format(time.RFC3339))
	s := Summary{
		StatusesPerModule: m.GetStatuses(),
		StartTime:         start.Format(time.RFC3339),
		EndTime:           end.Format(time.RFC3339),
		Duration:          end.Sub(start).String(),
	}
	enc := json.NewEncoder(zgrab2.GetMetaFile())
	if err := enc.Encode(&s); err != nil {
		log.Fatalf("unable to write summary: %s", err.Error())
	}
}
