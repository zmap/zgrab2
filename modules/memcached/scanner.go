package memcached

// Memcached protocal responses
// https://github.com/memcached/memcached/blob/master/doc/protocol.txt

// Package memcached provides a zgrab2 module that scans for memcache servers.
// Default port: 11211 (TCP)
import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
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
	_, err := zgrab2.AddCommand("memcached", "Distributed Memory Object Cache (Memcached)", module.Description(), 11211, &module)
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

// SnakeToCamel turns a snake case string to a camel case string
func SnakeToCamel(original string) (result string) {
	split := strings.Split(original, "_")
	for _, word := range split {
		result += strings.ToUpper(string(word[0])) + word[1:]
	}
	return result
}

// This function populates the MemcachedResult struct
func PopulateResults(trimmedResults []string) (resultStruct MemcachedResult) {
	var memcachedStats MemcachedResultStats
	for _, result := range trimmedResults {
		splitResult := strings.Split(result, " ")
		var value float64
		var err error
		if splitResult[0] != "version" && splitResult[0] != "libevent" {
			stringVal := string(splitResult[1])
			stringVal = strings.TrimSpace(stringVal)
			value, err = strconv.ParseFloat(string(stringVal), 64)
		}
		if errors.Is(err, strconv.ErrSyntax) {
			return
		}
		resultCamel := SnakeToCamel(splitResult[0])
		v := reflect.ValueOf(&memcachedStats).Elem()
		field := v.FieldByName(resultCamel)
		if field.IsValid() && field.CanSet() {
			switch field.Kind() {
			case reflect.Uint64:
				field.Set(reflect.ValueOf(uint64(value)))
			case reflect.Uint32:
				field.Set(reflect.ValueOf(uint32(value)))
			case reflect.Int32:
				field.Set(reflect.ValueOf(int32(value)))
			case reflect.Float64:
				field.SetFloat(float64(value))
			case reflect.Bool:
				field.SetBool(value == 1)
			case reflect.String:
				field.SetString(splitResult[1])
			default:
				continue
			}
		}
		switch splitResult[0] {
		case "version":
			resultStruct.Version = splitResult[1]
		case "libevent":
			resultStruct.LibeventVersion = splitResult[1]
		default:
			continue
		}
	}
	resultStruct.Stats = memcachedStats
	return resultStruct
}

// This function gets the first occurence of an integer in a string
func FirstInteger(str string) int {
	for index, char := range str {
		_, err := strconv.Atoi(string(char))
		if err == nil {
			return index
		}
	}
	return -1
}

// Struct for binary STAT response defined in:
// https://docs.memcached.org/protocols/binary/#stat
type statResponse struct {
	Magic       byte
	Opcode      byte
	KeyLength   uint16
	ExtraLength uint8
	DataType    byte
	Status      uint16
	TotalBody   uint32
	Opaque      uint32
	CAS         uint64
	Key         string
	Value       string
}

// Parse header according to:
//
//	https://docs.memcached.org/protocols/binary/#example-10
func ParseResponse(result []byte) statResponse {
	keyLength := binary.BigEndian.Uint16(result[2:4])
	totalBody := binary.BigEndian.Uint32(result[8:12])
	returnVal := statResponse{
		result[0],
		result[1],
		keyLength,
		result[4],
		result[5],
		binary.BigEndian.Uint16(result[6:8]),
		totalBody,
		binary.BigEndian.Uint32(result[12:16]),
		binary.BigEndian.Uint64(result[16:24]),
		string(result[24 : 24+keyLength]),
		string(result[24+keyLength : 24+totalBody])}

	return returnVal
}

// This function cleans binary results
func CleanBinary(results []byte) []string {
	var trimmedResults []string
	for len(results) > 24 {
		response := ParseResponse(results)
		stat := response.Key + " " + response.Value
		trimmedResults = append(trimmedResults, stat)
		results = results[24+response.TotalBody:]
	}
	return trimmedResults
}

// This function scans a memcached database using the ascii protocol
func ScanAscii(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, *MemcachedResult, error) {
	conn, err := dialGroup.Dial(ctx, target)

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to dial target (%s): %w", target.String(), err)
	}
	var message = []byte("stats")
	message = append(message, 0x0D, 0x0A)

	_, err = conn.Write(message)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to write target (%s): %w", target.String(), err)
	}

	results := make([]byte, 2000)
	results, err = zgrab2.ReadAvailableWithOptions(conn, len(results), 500*time.Millisecond, time.Second, len(results))
	result := MemcachedResult{}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to read target (%s): %w", target.String(), err)
	}
	splitResults := strings.Split(string(results), "\n")
	trimmedResults := make([]string, 0, len(splitResults))
	// Ignore empty last line of results and END message
	for _, result := range splitResults[:len(splitResults)-2] {

		trimmedResults = append(trimmedResults, strings.TrimSpace(strings.TrimPrefix(result, "STAT ")))
	}
	result = PopulateResults(trimmedResults)
	result.SupportsAscii = true
	defer func(conn net.Conn) {
		// cleanup conn
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)
	return zgrab2.TryGetScanStatus(err), &result, err
}

// Find server that doesn't support ASCII but supports binary
func ScanBinary(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, *MemcachedResult, error) {
	result := MemcachedResult{}

	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to dial target (%s): %w", target.String(), err)
	}

	// Send the binary "stat" command - From https://docs.memcached.org/protocols/binary/#stat
	var message []byte
	message = append(message, 0x80, 0x10, 0x00, 0x00)

	// Add padding to make message necessary length of 24 bytes
	message = append(message, make([]byte, 20)...)
	for i := 0; i < 20; i++ {
		message = append(message, byte(0x00))
	}

	_, err = conn.Write(message)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to write target (%s): %w", target.String(), err)
	}

	results := make([]byte, 4000)
	results, err = zgrab2.ReadAvailableWithOptions(conn, len(results), 500*time.Millisecond, 0, len(results))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to read target (%s): %w", target.String(), err)
	}

	trimmedResults := CleanBinary(results)
	result = PopulateResults(trimmedResults)
	result.SupportsBinary = true

	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)
	return zgrab2.TryGetScanStatus(err), &result, err
}

// Scan probes for a memcached service.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	_, asciiResult, asciiErr := ScanAscii(ctx, dialGroup, target)
	_, binaryResult, binaryErr := ScanBinary(ctx, dialGroup, target)

	if asciiResult == nil && binaryResult == nil {
		return zgrab2.TryGetScanStatus(asciiErr), nil, fmt.Errorf("target supports neither ascii or binary (%s): %w", target.String(), asciiErr)
	}
	if asciiResult == nil && binaryResult != nil {
		return zgrab2.TryGetScanStatus(binaryErr), *binaryResult, binaryErr
	} else if asciiResult != nil && binaryResult == nil {
		return zgrab2.TryGetScanStatus(asciiErr), *asciiResult, asciiErr
	} else {
		asciiResult.SupportsBinary = binaryResult.SupportsBinary
		return zgrab2.TryGetScanStatus(asciiErr), *asciiResult, asciiErr
	}
}
