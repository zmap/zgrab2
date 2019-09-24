package bin

import (
	"encoding/json"
	"os"
	"runtime/pprof"
	"time"

	"fmt"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	flags "github.com/zmap/zflags"
	"github.com/zmap/zgrab2"
)

// Get the value of the ZGRAB2_MEMPROFILE variable (or the empty string).
// This may include {TIMESTAMP} or {NANOS}, which should be replaced using
// getFormattedFile().
func getMemProfileFile() string {
	return os.Getenv("ZGRAB2_MEMPROFILE")
}

// Get the value of the ZGRAB2_CPUPROFILE variable (or the empty string).
// This may include {TIMESTAMP} or {NANOS}, which should be replaced using
// getFormattedFile().
func getCPUProfileFile() string {
	return os.Getenv("ZGRAB2_CPUPROFILE")
}

// Replace instances in formatString of {TIMESTAMP} with when formatted as
// YYYYMMDDhhmmss, and {NANOS} as the decimal nanosecond offset.
func getFormattedFile(formatString string, when time.Time) string {
	timestamp := when.Format("20060102150405")
	nanos := fmt.Sprintf("%d", when.Nanosecond())
	ret := strings.Replace(formatString, "{TIMESTAMP}", timestamp, -1)
	ret = strings.Replace(ret, "{NANOS}", nanos, -1)
	return ret
}

// If memory profiling is enabled (ZGRAB2_MEMPROFILE is not empty), perform a GC
// then write the heap profile to the profile file.
func dumpHeapProfile() {
	if file := getMemProfileFile(); file != "" {
		now := time.Now()
		fullFile := getFormattedFile(file, now)
		f, err := os.Create(fullFile)
		if err != nil {
			log.Fatal("could not create heap profile: ", err)
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write heap profile: ", err)
		}
		f.Close()
	}
}

// If CPU profiling is enabled (ZGRAB2_CPUPROFILE is not empty), start tracking
// CPU profiling in the configured file. Caller is responsible for invoking
// stopCPUProfile() when finished.
func startCPUProfile() {
	if file := getCPUProfileFile(); file != "" {
		now := time.Now()
		fullFile := getFormattedFile(file, now)
		f, err := os.Create(fullFile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
	}
}

// If CPU profiling is enabled (ZGRAB2_CPUPROFILE is not empty), stop profiling
// CPU usage.
func stopCPUProfile() {
	if getCPUProfileFile() != "" {
		pprof.StopCPUProfile()
	}
}

// ZGrab2Main should be called by func main() in a binary. The caller is
// responsible for importing any modules in use. This allows clients to easily
// include custom sets of scan modules by creating new main packages with custom
// sets of ZGrab modules imported with side-effects.
func ZGrab2Main() {
	startCPUProfile()
	defer stopCPUProfile()
	defer dumpHeapProfile()
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
	monitor.Callback = func(_ string) {
		dumpHeapProfile()
	}
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
