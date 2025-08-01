package bin

import (
	"encoding/json"
	"os"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"

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
	nanos := strconv.Itoa(when.Nanosecond())
	ret := strings.ReplaceAll(formatString, "{TIMESTAMP}", timestamp)
	ret = strings.ReplaceAll(ret, "{NANOS}", nanos)
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
func startCPUProfile() *os.File {
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
		return f
	}

	return nil
}

// If CPU profiling is enabled (ZGRAB2_CPUPROFILE is not empty), stop profiling
// CPU usage.
func stopCPUProfile(f *os.File) {
	if getCPUProfileFile() != "" {
		pprof.StopCPUProfile()
	}
	if f != nil {
		f.Close()
	}
}

// ZGrab2Main should be called by func main() in a binary. The caller is
// responsible for importing any modules in use. This allows clients to easily
// include custom sets of scan modules by creating new main packages with custom
// sets of ZGrab modules imported with side-effects.
func ZGrab2Main() {
	f := startCPUProfile()
	defer stopCPUProfile(f)
	defer dumpHeapProfile()
	// We parse and re-parse the CLI args here as follows:
	// 0. CLI config is initialized in init() with default values. These are communicated to user in flag descriptions.
	// 1. Parse the CLI flag args to get the module type and flags.
	// 2. If this is a Multiple command, we'll parse the ini file passed in either stdin or a file. This will overwrite
	//    any flags set in the CLI args if also set in the ini file.
	// 3. Re-parse the CLI args to ensure that they have precedence. This follows CLI app conventions of CLI args taking
	//    precedence over config files.
	// 4. Validate the framework configuration, which will ensure that the flags are valid and

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
		var flagsReturned []any
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
		// Re-parse the CLI args to ensure that they have precedence over the ini file.
		_, _, _, err = zgrab2.ParseCommandLine(os.Args[1:])
		if err != nil {
			log.Fatalf("could not parse flags: %s", err)
		}
		// The iniParser will have overwritten config values that were set first in zgrab2.ParseCommandLine using argv values.
		// We need to re-validate the framework configuration after parsing the ini file itself.
		for i, fl := range flagsReturned {
			f, ok := fl.(zgrab2.ScanFlags)
			if !ok {
				log.Fatalf("error parsing flags as ScanFlags")
			}
			mod := zgrab2.GetModule(modTypes[i])
			s := mod.NewScanner()

			if err = s.Init(f); err != nil {
				log.Panicf("could not initialize multiple scanner: %v", err)
			}
			zgrab2.RegisterScan(s.GetName(), s)
		}
	} else {
		mod := zgrab2.GetModule(moduleType)
		s := mod.NewScanner()
		if err = s.Init(flag); err != nil {
			log.Panicf("could not initialize scanner %s: %v", moduleType, err)
		}
		zgrab2.RegisterScan(moduleType, s)
	}
	zgrab2.ValidateAndHandleFrameworkConfiguration() // will panic if there is an error
	wg := sync.WaitGroup{}
	monitor := zgrab2.MakeMonitor(1, &wg)
	monitor.Callback = func(_ string) {
		dumpHeapProfile()
	}
	start := time.Now()
	log.Infof("started grab at %s", start.Format(time.RFC3339))
	zgrab2.Process(monitor)
	end := time.Now()
	log.Infof("finished grab at %s", end.Format(time.RFC3339))
	monitor.Stop()
	wg.Wait()
	s := Summary{
		StatusesPerModule: monitor.GetStatuses(),
		StartTime:         start.Format(time.RFC3339),
		EndTime:           end.Format(time.RFC3339),
		Duration:          end.Sub(start).String(),
	}
	if metadataFile := zgrab2.GetMetaFile(); metadataFile != nil {
		if err := json.NewEncoder(zgrab2.GetMetaFile()).Encode(&s); err != nil {
			log.Fatalf("unable to write metadata summary: %s", err.Error())
		}
	}
}
