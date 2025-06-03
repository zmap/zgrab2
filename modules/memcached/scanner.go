package memcached

// Memcached protocal responses
// https://github.com/memcached/memcached/blob/master/doc/protocol.txt

// Package memcached provides a zgrab2 module that scans for memcache servers.
// Default port: 11211 (TCP)
import (
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

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
func (flags *Flags) Validate([]string) error {
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
	SupportsAscii   bool                 `json:"supports_ascii"`  // true if the server supports plain-text ASCII protocol
	SupportsBinary  bool                 `json:"supports_binary"` // true if the server supports binary protocol
	Stats           MemcachedResultStats `json:"stats"`
}

type MemcachedResultStats struct {
	Pid                       uint32  `json:"pid"`
	Uptime                    uint32  `json:"uptime"`
	Time                      uint32  `json:"time"`
	PointerSize               int32   `json:"pointer_size"`
	RusageUser                float64 `json:"rusage_user"`
	RusageSystem              float64 `json:"rusage_system"`
	CurrItems                 uint64  `json:"curr_items"`
	TotalItems                uint64  `json:"total_items"`
	Bytes                     uint64  `json:"bytes"`
	MaxConnections            uint32  `json:"max_connections"`
	CurrConnections           uint32  `json:"curr_connections"`
	TotalConnections          uint32  `json:"total_connections"`
	RejectedConnections       uint64  `json:"rejected_connections"`
	ConnectionStructures      uint32  `json:"connected_structures"`
	ResponseObjOom            uint64  `json:"response_obj_oom"`
	ResponseObjCount          uint64  `json:"response_obj_count"`
	ResponseObjBytes          uint64  `json:"response_obj_bytes"`
	ReadBufCount              uint64  `json:"read_buf_count"`
	ReadBufBytes              uint64  `json:"read_buf_bytes"`
	ReadBufBytesFree          uint64  `json:"read_buf_bytes_free"`
	ReadBufOom                uint64  `json:"read_buf_oom"`
	ReservedFds               uint32  `json:"reserved_fds"`
	ProxyConnRequests         uint64  `json:"proxy_conn_requests"`
	ProxyConnErrors           uint64  `json:"proxy_conn_errors"`
	ProxyConnOom              uint64  `json:"proxy_conn_oom"`
	ProxyReqActive            uint64  `json:"proxy_req_active"`
	ProxyReqAwait             uint64  `json:"proxy_req_await"`
	CmdGet                    uint64  `json:"cmd_get"`
	CmdSet                    uint64  `json:"cmd_set"`
	CmdFlush                  uint64  `json:"cmd_flush"`
	CmdTouch                  uint64  `json:"cmd_touch"`
	GetHits                   uint64  `json:"get_hits"`
	GetMisses                 uint64  `json:"get_misses"`
	GetExpired                uint64  `json:"get_expired"`
	GetFlushed                uint64  `json:"get_flushed"`
	DeleteMisses              uint64  `json:"delete_misses"`
	DeleteHits                uint64  `json:"delete_hits"`
	IncrMisses                uint64  `json:"incr_misses"`
	IncrHits                  uint64  `json:"incr_hits"`
	DecrMisses                uint64  `json:"decr_misses"`
	DecrHits                  uint64  `json:"decr_hits"`
	CasMisses                 uint64  `json:"cas_misses"`
	CasHits                   uint64  `json:"cas_hits"`
	CasBadval                 uint64  `json:"cas_badval"`
	TouchHits                 uint64  `json:"touch_hits"`
	TouchMisses               uint64  `json:"touch_misses"`
	StoreTooLarge             uint64  `json:"store_too_large"`
	StoreNoMemory             uint64  `json:"store_no_memory"`
	AuthCmds                  uint64  `json:"auth_cmds"`
	AuthErrors                uint64  `json:"auth_errors"`
	IdleKicks                 uint64  `json:"idle_kicks"`
	Evictions                 uint64  `json:"evictions"`
	Reclaimed                 uint64  `json:"reclaimed"`
	BytesRead                 uint64  `json:"bytes_read"`
	BytesWritten              uint64  `json:"bytes_written"`
	LimitMaxbytes             uint64  `json:"limit_maxbytes"`
	AcceptingConns            bool    `json:"accepting_conns"`
	ListenDisabledNum         uint64  `json:"listen_disabled_num"`
	TimeInListenDisabledUs    uint64  `json:"time_in_listen_disabled_us"`
	Threads                   uint32  `json:"threads"`
	ConnYields                uint64  `json:"conn_yields"`
	HashPowerLevel            uint32  `json:"hash_power_level"`
	HashBytes                 uint64  `json:"hash_bytes"`
	HashIsExpanding           bool    `json:"hash_is_expanding"`
	ExpiredUnfetched          uint64  `json:"expired_unfetched"`
	EvictedUnfetched          uint64  `json:"evicted_unfetched"`
	EvictedActive             uint64  `json:"evicted_active"`
	SlabReassignRunning       bool    `json:"slab_reassign_running"`
	SlabsMoved                uint64  `json:"slabs_moved"`
	CrawlerReclaimed          uint64  `json:"crawler_reclaimed"`
	CrawlerItemsChecked       uint64  `json:"crawler_items_checked"`
	LrutailReflocked          uint64  `json:"lrutail_reflocked"`
	MovesToCold               uint64  `json:"moves_to_cold"`
	MovesToWarm               uint64  `json:"moves_to_warm"`
	MovesWithinLru            uint64  `json:"moves_within_lru"`
	DirectReclaims            uint64  `json:"direct_reclaims"`
	LruCrawlerStarts          uint64  `json:"lru_crawler_starts"`
	LruMaintainerJuggles      uint64  `json:"lru_maintainer_juggles"`
	SlabGlobalPagePool        uint32  `json:"slab_global_page_pool"`
	SlabReassignRescues       uint64  `json:"slab_reassign_rescues"`
	SlabReassignChunkRescues  uint64  `json:"slab_reassign_chunk_rescues"`
	SlabReassignInlineReclaim uint64  `json:"slab_reassign_inline_reclaim"`
	SlabReassignBusyItems     uint64  `json:"slab_reassign_busy_items"`
	SlabReassignBusyNomem     uint64  `json:"slab_reassign_busy_nomem"`
	SlabReassignBusyDeletes   uint64  `json:"slab_reassign_busy_deletes"`
	LogWorkerDropped          uint64  `json:"log_worker_dropped"`
	LogWorkerWritten          uint64  `json:"log_worker_written"`
	LogWatcherSkipped         uint64  `json:"log_watcher_skipped"`
	LogWatcherSent            uint64  `json:"log_watcher_sent"`
	LogWatchers               uint64  `json:"log_watchers"`
	UnexpectedNapiIds         uint64  `json:"unexpected_napi_ids"`
	RoundRobinFallback        uint64  `json:"round_robin_fallback"`
}

func SnakeToCamel(original string) (result string) {
	split := strings.Split(original, "_")
	for _, word := range split {
		result += strings.ToUpper(string(word[0])) + word[1:]
	}
	return result
}

func PopulateResults(trimmed_results []string) (result_struct MemcachedResult) {
	result_struct.Version = trimmed_results[0]
	var memcached_stats MemcachedResultStats
	for _, result := range trimmed_results {
		split_result := strings.Split(result, " ")
		var value float64
		var err error
		if split_result[0] != "version" && split_result[0] != "libevent" {
			string_val := string(split_result[1])
			string_val = strings.TrimSpace(string_val)
			value, err = strconv.ParseFloat(string(string_val), 64)
		}
		if err == strconv.ErrSyntax {
			return
		}
		result_camel := SnakeToCamel(split_result[0])
		v := reflect.ValueOf(&memcached_stats).Elem()
		field := v.FieldByName(result_camel)
		if field.IsValid() && field.CanSet() {
			if field.Type() == reflect.TypeOf(uint64(1)) {
				field.Set(reflect.ValueOf(uint64(value)))
			} else if field.Type() == reflect.TypeOf(uint32(1)) {
				field.Set(reflect.ValueOf(uint32(value)))
			} else if field.Type() == reflect.TypeOf(int32(1)) {
				field.Set(reflect.ValueOf(int32(value)))
			} else if field.Type() == reflect.TypeOf(float64(0.5)) {
				field.SetFloat(float64(value))
			} else if field.Type() == reflect.TypeOf(true) {
				field.SetBool(value == 1)
			} else if field.Type() == reflect.TypeOf("") {
				field.SetString(split_result[1])
			}
		}
		switch split_result[0] {
		case "version":
			result_struct.Version = split_result[1]
		case "libevent":
			result_struct.LibeventVersion = split_result[1]
		}
	}
	result_struct.Stats = memcached_stats
	return result_struct
}

func scan_ascii(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, *MemcachedResult, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to dial target (%s): %w", target.String(), err)
	}
	var message = []byte("stats")
	message = append(message, byte(0x0D))
	message = append(message, byte(0x0A))

	_, err = conn.Write(message)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to write target (%s): %w", target.String(), err)
	}

	results := make([]byte, 2000)
	results, err = zgrab2.ReadAvailableWithOptions(conn, len(results), 500*time.Millisecond, 0, len(results))

	result := MemcachedResult{}
	if err == nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to write target (%s): %w", target.String(), err)
	}
	split_results := strings.Split(string(results), "\n")
	trimmed_results := make([]string, 0, len(split_results))
	for _, result := range split_results[:len(split_results)-2] {

		trimmed_results = append(trimmed_results, strings.TrimSpace(strings.TrimPrefix(result, "STAT ")))
	}
	result = PopulateResults(trimmed_results)
	result.SupportsAscii = true
	defer func(conn net.Conn) {
		// cleanup conn
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)

	return zgrab2.TryGetScanStatus(err), &result, err
}

func scan_binary(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, *MemcachedResult, error) {
	result := MemcachedResult{}

	binary_conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to write target (%s): %w", target.String(), err)
	}

	var binaryMessage []byte
	binaryMessage = append(binaryMessage, byte(0x80))
	binaryMessage = append(binaryMessage, byte(0x0b))
	binaryMessage = append(binaryMessage, byte(0x00))
	binaryMessage = append(binaryMessage, byte(0x00))
	for i := 0; i < 20; i++ {
		binaryMessage = append(binaryMessage, byte(0x00))
	}

	_, err = binary_conn.Write(binaryMessage)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to write target (%s): %w", target.String(), err)
	}

	binary_results := make([]byte, 2000)
	binary_results, err = zgrab2.ReadAvailableWithOptions(binary_conn, len(binary_results), 500*time.Millisecond, 0, len(binary_results))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to write target (%s): %w", target.String(), err)
	}
	version_string := string(binary_results[24:])
	re := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	if re.MatchString(version_string) {
		result.SupportsBinary = true
	}
	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(binary_conn)
	return zgrab2.TryGetScanStatus(err), &result, err
}

// Scan probes for a memcached service.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	_, ascii_result, ascii_err := scan_ascii(ctx, dialGroup, target)
	_, binary_result, binary_err := scan_binary(ctx, dialGroup, target)

	if ascii_result == nil && binary_result == nil {
		return zgrab2.TryGetScanStatus(ascii_err), nil, fmt.Errorf("target supports neither ascii or binary (%s): %w", target.String(), ascii_err)
	}
	if ascii_result == nil && binary_result != nil {
		return zgrab2.TryGetScanStatus(binary_err), *binary_result, binary_err
	} else if ascii_result != nil && binary_result == nil {
		return zgrab2.TryGetScanStatus(ascii_err), *ascii_result, ascii_err
	} else {
		ascii_result.SupportsBinary = binary_result.SupportsBinary
		return zgrab2.TryGetScanStatus(ascii_err), *ascii_result, ascii_err
	}
}
