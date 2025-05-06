package memcached

// Memcached protocal responses
// https://github.com/memcached/memcached/blob/master/doc/protocol.txt

// Package memcached provides a zgrab2 module that scans for memcache servers.
// Default port: 11211 (TCP)
import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the memcached scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("memcached", "memcached", module.Description(), 11211, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for memcached services"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate() error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "memcached"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

type MemcachedResult struct {
	Version         string               `json:"version"`
	LibeventVersion string               `json:"libevent_version"`
	SupportsAscii   bool                 `json:"supports_ascii"` // true if the server supports plain-text ASCII protocol
	PointerSize     int                  `json:"pointer_size"`   // move to stats
	Stats           MemcachedResultStats `json:"stats"`

	// TODO - Add more fields as needed
}

type MemcachedResultStats struct {
	// Unsure of what to put in Stats vs Result
	PID                  int     `json:"pid"`
	Uptime               int     `json:"uptime"`
	Time                 int     `json:"time"`
	RUsageUser           float64 `json:"rusuage_user"`
	RUsageSystem         float64 `json:"rusuage_system"`
	CurrConnections      int     `json:"curr_connections"`
	TotalConnections     int     `json:"total_connections"`
	ConnectionStructures int     `json:"connection_structures"`
	ReservedFds          int     `json:"reserved_fds"`
	CmdGet               int     `json:"cmd_get"`
	CmdSet               int     `json:"cmd_set"`
	CmdFlush             int     `json:"cmd_flush"`
	CmdTouch             int     `json:"cmd_touch"`
	GetHits              int     `json:"get_hits"`
	GetMisses            int     `json:"get_misses"`
	DeleteMisses         int     `json:"delete_misses"`
	DeleteHits           int     `json:"delete_hits"`
	IncrMisses           int     `json:"incr_misses"`
	IncrHits             int     `json:"incr_hits"`
	DecrMisses           int     `json:"decr_misses"`
	DecrHits             int     `json:"decr_hits"`
	CasMisses            int     `json:"cas_misses"`
	CasHits              int     `json:"cas_hits"`
	CasBadval            int     `json:"cas_badval"`
	TouchHits            int     `json:"touch_hits"`
	TouchMisses          int     `json:"touch_misses"`
	AuthCmds             int     `json:"auth_cmds"`
	AuthErrors           int     `json:"auth_errors"`
	BytesRead            int     `json:"bytes_read"`
	BytesWritten         int     `json:"bytes_written"`
	LimitMaxBytes        int     `json:"limit_maxbytes"`
	AcceptingConns       bool    `json:"accepting_conns"`
	ListenDisabledNum    int     `json:"listen_disabled_num"`
	Threads              int     `json:"threads"`
	ConnYields           int     `json:"conn_yields"`
	HashPowerLevel       int     `json:"hash_power_level"`
	HashBytes            int     `json:"hash_bytes"`
	HashIsExpanding      bool    `json:"hash_is_expanding"`
	Bytes                int     `json:"bytes"`
	CurrItems            int     `json:"curr_items"`
	TotalItems           int     `json:"total_items"`
	ExpiredUnfetched     int     `json:"expired_unfetched"`
	EvictedUnfetched     int     `json:"evicted_unfetched"`
	Evictions            int     `json:"evictions"`
	Reclaimed            int     `json:"reclaimed"`

	// TODO - Add fields for memcached stats
}

// TODO - Add more commands ex. stats settings
// TODO - Figure out supports ASCII
// USE Reflect to access struct field by string
// Function to convert snake case into camel case
// TODO - Change size of variables
func PopulateResults(trimmed_results []string) (result_struct MemcachedResult) {
	result_struct.Version = trimmed_results[0]
	var memcached_stats MemcachedResultStats
	for _, result := range trimmed_results {
		split_result := strings.Split(result, " ")
		var value float64
		var err error
		// println(result)
		// println(split_result[0] == "version" || split_result[0] == "libevent")
		if split_result[0] != "version" || split_result[0] != "libevent" {
			value, err = strconv.ParseFloat(split_result[1], 32)
		}
		if err == strconv.ErrSyntax {
			return
		}
		switch split_result[0] {
		case "pid":
			memcached_stats.PID = int(value)
		case "uptime":
			memcached_stats.Uptime = int(value)
		case "time":
			memcached_stats.Time = int(value)
		case "version":
			result_struct.Version = split_result[1]
		case "libevent":
			result_struct.LibeventVersion = split_result[1]
		case "pointer_size":
			result_struct.PointerSize = int(value)
		case "rusuage_user":
			memcached_stats.RUsageUser = value
		case "rusage_system":
			memcached_stats.RUsageSystem = value
		case "curr_connections":
			memcached_stats.CurrConnections = int(value)
		case "total_connections":
			memcached_stats.TotalConnections = int(value)
		case "connection_structures":
			memcached_stats.ConnectionStructures = int(value)
		case "reserved_fds":
			memcached_stats.ReservedFds = int(value)
		case "cmd_get":
			memcached_stats.CmdGet = int(value)
		case "cmd_set":
			memcached_stats.CmdSet = int(value)
		case "cmd_flush":
			memcached_stats.CmdFlush = int(value)
		case "cmd_touch":
			memcached_stats.CmdTouch = int(value)
		case "get_hits":
			memcached_stats.GetHits = int(value)
		case "get_misses":
			memcached_stats.GetMisses = int(value)
		case "delete_misses":
			memcached_stats.DeleteMisses = int(value)
		case "delete_hits":
			memcached_stats.DeleteHits = int(value)
		case "incr_misses":
			memcached_stats.IncrMisses = int(value)
		case "incr_hits":
			memcached_stats.IncrHits = int(value)
		case "decr_misses":
			memcached_stats.DecrMisses = int(value)
		case "decr_hits":
			memcached_stats.DecrHits = int(value)
		case "cas_misses":
			memcached_stats.CasMisses = int(value)
		case "cas_hits":
			memcached_stats.CasHits = int(value)
		case "cas_badval":
			memcached_stats.CasBadval = int(value)
		case "touch_hits":
			memcached_stats.TouchHits = int(value)
		case "touch_misses":
			memcached_stats.TouchMisses = int(value)
		case "auth_cmds":
			memcached_stats.AuthCmds = int(value)
		case "auth_errors":
			memcached_stats.AuthErrors = int(value)
		case "bytes_read":
			memcached_stats.BytesRead = int(value)
		case "bytes_written":
			memcached_stats.BytesWritten = int(value)
		case "limit_maxbytes":
			memcached_stats.LimitMaxBytes = int(value)
		case "accepting_conns":
			memcached_stats.AcceptingConns = int(value) == 1
		case "listen_disabled_num":
			memcached_stats.ListenDisabledNum = int(value)
		case "threads":
			memcached_stats.Threads = int(value)
		case "conn_yields":
			memcached_stats.ConnYields = int(value)
		case "hash_power_level":
			memcached_stats.HashPowerLevel = int(value)
		case "hash_bytes":
			memcached_stats.HashBytes = int(value)
		case "hash_is_expanding":
			memcached_stats.HashIsExpanding = int(value) == 1
		case "bytes":
			memcached_stats.Bytes = int(value)
		case "curr_items":
			memcached_stats.CurrItems = int(value)
		case "total_items":
			memcached_stats.TotalItems = int(value)
		case "expired_unfetched":
			memcached_stats.ExpiredUnfetched = int(value)
		case "evicted_unfetched":
			memcached_stats.EvictedUnfetched = int(value)
		case "evictions":
			memcached_stats.Evictions = int(value)
		case "reclaimed":
			memcached_stats.Reclaimed = int(value)
		default:
			// If we get back a key we don't know what to do with, put in JSON file
			// of what we don't know what to handle
			fmt.Println(os.Stderr, "ERROR: No matching field in struct for value")
		}
	}
	result_struct.Stats = memcached_stats
	return result_struct
}

// Scan probes for a memcached service.
// TODO - Describe Scan process
// TODO - Make Map for everything
// DO NOT USE stats sizes
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	// Write stats
	var message []byte = []byte("stats")
	message = append(message, byte(0x0D))
	message = append(message, byte(0x0A))
	_, err = conn.Write(message)
	// println(message)
	// println(target.Port)
	// Want read to get data
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to dial target (%s): %w", target.String(), err)
	}

	// var results []byte
	// TODO: Fix Length
	// 0d 0a ends reply
	results := make([]byte, 2000)
	_, err = conn.Read(results)
	// print("error", err)
	// println("Results", results)
	// print("Results (string)", string(results))
	split_results := strings.Split(string(results), "\n")
	trimmed_results := make([]string, 0, len(split_results))
	for _, result := range split_results[:len(split_results)-2] {
		// fmt.Println(string(result) == "END\n")
		// if len(result) > 4 { // Don't include after END
		// Break if we hit END, prefixContains
		trimmed_results = append(trimmed_results, strings.TrimPrefix(result, "STAT "))
		// }
	}
	// for i, result := range trimmed_results {
	// 	fmt.Println(i, result)
	// 	if i == 48 {
	// 		println(result)
	// 		println([]byte(string(result)))
	// 		println([]byte(result)[0], []byte(result)[1], []byte(result)[2], []byte(result)[3])
	// 		println(string(0x14000014c0c))
	// 		println(len(result))
	// }
	// }
	defer func(conn net.Conn) {
		// cleanup conn
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)

	// result := new(MemcachedResult)
	result := PopulateResults(trimmed_results)
	// TODO - populate memcached result

	return zgrab2.TryGetScanStatus(err), result, err
}
