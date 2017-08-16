package main

import (
	"os"

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
	//start := time.Now()
	zgrab2.Process(m)
	zgrab2.PrintLookup()
	/*end := time.Now()
	s := Summary{
		StatusesPerModule: m.GetStatuses(),
		StartTime:         start,
		EndTime:           end,
		Duration:          end.Sub(start),
	}
	//enc := json.NewEncoder(metadataFile)
	if err := enc.Encode(&s); err != nil {
		log.Fatalf("unable to write summary: %s", err.Error())
	}*/
}
