package main

import (
	"encoding/json"
	"os"
	"time"

	flags "github.com/zmap/zflags"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	_ "github.com/zmap/zgrab2/modules"
)

func main() {
	_, moduleType, flag, err := zgrab2.ParseCommandLine(os.Args[1:])
	// Blanked arg is positional arguments
	if err != nil {
		// Outputting help is returned as an error. Exit successfuly on help output.
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			return
		}

		// Didn't output help. Unknown parsing error.
		log.Fatalf("could not parse flags: %s", err)
	}

	if m, ok := flag.(*zgrab2.MultipleCommand); ok {
		iniParser := zgrab2.NewIniParser()
		var modTypes []string
		var flagsReturned []interface{}
		if m.ConfigFileName == "-" {
			modTypes, flagsReturned, err = iniParser.Parse(os.Stdin)
		} else {
			modTypes, flagsReturned, err = iniParser.ParseFile(m.ConfigFileName)
		}
		if err != nil {
			log.Fatalf("could not parse multiple: %s", err)
		}
		if len(modTypes) != len(flagsReturned) {
			log.Fatalf("error parsing flags")
		}
		for i, fl := range flagsReturned {
			f, _ := fl.(zgrab2.ScanFlags)
			mod := zgrab2.GetModule(modTypes[i])
			s := mod.NewScanner()
			s.Init(f)
			zgrab2.RegisterScan(s.GetName(), s)
		}
	} else {
		mod := zgrab2.GetModule(moduleType)
		s := mod.NewScanner()
		s.Init(flag)
		zgrab2.RegisterScan(moduleType, s)
	}
	monitor := zgrab2.MakeMonitor()
	start := time.Now()
	log.Infof("started grab at %s", start.Format(time.RFC3339))
	zgrab2.Process(monitor)
	end := time.Now()
	log.Infof("finished grab at %s", end.Format(time.RFC3339))
	s := Summary{
		StatusesPerModule: monitor.GetStatuses(),
		StartTime:         start.Format(time.RFC3339),
		EndTime:           end.Format(time.RFC3339),
		Duration:          end.Sub(start).String(),
	}
	enc := json.NewEncoder(zgrab2.GetMetaFile())
	if err := enc.Encode(&s); err != nil {
		log.Fatalf("unable to write summary: %s", err.Error())
	}
}
