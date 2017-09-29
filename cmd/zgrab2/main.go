package main

import (
	"encoding/json"
	"os"
	"time"

	flags "github.com/ajholland/zflags"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	_ "github.com/zmap/zgrab2/zmodules"
)

func main() {
	_, modType, fl, err := zgrab2.ParseCommandLine(os.Args[1:])
	if err != nil { //blanked arg is positional arguments
		// Outputting help is returned as an error. Exit successfuly on help output.
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			return
		}

		// Didn't output help. Unknown parsing error.
		log.Fatalf("could not parse flags: %s", err)
	}

	if modType == "multiple" {
		iniParser := zgrab2.NewIniParser()
		m, _ := fl.(*zgrab2.MultipleCommand)
		if m.ConfigFileName == "-" {
			err = iniParser.Parse(os.Stdin)
		} else {
			err = iniParser.ParseFile(m.ConfigFileName)
		}
		if err != nil {
			log.Fatalf("could not parse multiple: %s", err)
		}
	} else {
		f, _ := fl.(zgrab2.ScanFlags)
		mod := *zgrab2.GetModule(modType)
		s := mod.NewScanner()
		s.Init(f)
		zgrab2.RegisterScan(modType, s)
	}
	zgrab2.PrintScanners()
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
