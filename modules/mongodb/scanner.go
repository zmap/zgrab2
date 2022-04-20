package mongodb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"gopkg.in/mgo.v2/bson"
)

// Module implements the zgrab2.Module interface
type Module struct {
}

// Flags contains mongodb-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags
}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config              *Flags
	isMasterMsg         []byte
	buildInfoCommandMsg []byte
	buildInfoOpMsg      []byte
}

// scan holds the state for the scan of an individual target
type scan struct {
	scanner *Scanner
	result  *Result
	target  *zgrab2.ScanTarget
	conn    *Connection
	close   func()
}

// Close cleans up the scanner.
func (scan *scan) Close() {
	defer scan.close()
}

// getIsMasterMsg returns a mongodb message containing isMaster command.
// https://docs.mongodb.com/manual/reference/command/isMaster/
func getIsMasterMsg() []byte {
	query, err := bson.Marshal(bson.M{"isMaster": 1})
	if err != nil {
		// programmer error
		log.Fatalf("Invalid BSON: %v", err)
	}
	query_msg := getOpQuery("admin.$cmd", query)
	return query_msg
}

// getBuildInfoQuery returns a mongodb message containing a command to retrieve MongoDB build info.
func getBuildInfoQuery() []byte {
	query, err := bson.Marshal(bson.M{"buildinfo": 1})
	if err != nil {
		// programmer error
		log.Fatalf("Invalid BSON: %v", err)
	}
	query_msg := getOpQuery("admin.$cmd", query)
	return query_msg
}

// getOpQuery returns a mongodb OP_QUERY message containing the specified BSON-encoded query.
// query expected to be BSON byte array.
func getOpQuery(collname string, query []byte) []byte {
	flagslen := 4
	collname_len := len(collname) + 1
	nskiplen := 4
	nretlen := 4
	qlen := len(query)
	msglen := MSGHEADER_LEN + flagslen + collname_len + nskiplen + nretlen + qlen
	out := make([]byte, msglen)
	// msg header
	binary.LittleEndian.PutUint32(out[0:], uint32(msglen))
	binary.LittleEndian.PutUint32(out[12:], OP_QUERY)
	// query msg
	idx := MSGHEADER_LEN + flagslen
	copy(out[idx:idx+collname_len], []byte(collname))
	idx += collname_len + nskiplen
	binary.LittleEndian.PutUint32(out[idx:idx+nretlen], 1)
	idx += nretlen
	copy(out[idx:idx+qlen], query)
	return out
}

// getOpMsg returns a mongodb OP_MSG message containing the specified BSON-encoded command.
// section expected to be BSON byte array.
func getOpMsg(section []byte) []byte {
	flagslen := 4
	slen := len(section)
	msglen := MSGHEADER_LEN + flagslen + slen
	out := make([]byte, msglen)
	// msg header
	binary.LittleEndian.PutUint32(out[0:], uint32(msglen))
	binary.LittleEndian.PutUint32(out[12:], OP_MSG)
	// command msg
	idx := MSGHEADER_LEN + flagslen
	copy(out[idx:idx+slen], []byte(section))
	return out
}

// getBuildInfoOpMsg returns a mongodb "OP" message containing query to retrieve MongoDB build info.
func getBuildInfoOpMsg() []byte {
	// gleaned from tshark
	section_payload, err := bson.Marshal(bson.M{"buildinfo": 1, "$db": "admin"})
	if err != nil {
		// programmer error
		log.Fatalf("Invalid BSON: %v", err)
	}
	section := make([]byte, len(section_payload)+1)
	copy(section[1:], section_payload)
	op_msg := getOpMsg(section)
	return op_msg
}

// BuildEnvironment_t holds build environment information returned by scan.
type BuildEnvironment_t struct {
	Distmod    string `bson:"distmod,omitempty" json:"dist_mod,omitempty"`
	Distarch   string `bson:"distarch,omitempty" json:"dist_arch,omitempty"`
	Cc         string `bson:"cc,omitempty" json:"cc,omitempty"`
	CcFlags    string `bson:"ccflags,omitempty" json:"cc_flags,omitempty"`
	Cxx        string `bson:"cxx,omitempty" json:"cxx,omitempty"`
	CxxFlags   string `bson:"cxxflags,omitempty" json:"cxx_flags,omitempty"`
	LinkFlags  string `bson:"linkflags,omitempty" json:"link_flags,omitempty"`
	TargetArch string `bson:"target_arch,omitempty" json:"target_arch,omitempty"`
	TargetOS   string `bson:"target_os,omitempty" json:"target_os,omitempty"`
}

// BuildInfo_t holds the data returned by the the buildInfo query
type BuildInfo_t struct {
	Version          string             `bson:"version,omitempty" json:"version,omitempty"`
	GitVersion       string             `bson:"gitVersion,omitempty" json:"git_version,omitempty"`
	BuildEnvironment BuildEnvironment_t `bson:"buildEnvironment,omitempty" json:"build_environment,omitempty"`
}

// IsMaster_t holds the data returned by an isMaster query
type IsMaster_t struct {
	IsMaster                     bool  `bson:"ismaster" json:"is_master"`
	MaxWireVersion               int32 `bson:"maxWireVersion,omitempty" json:"max_wire_version,omitempty"`
	MinWireVersion               int32 `bson:"minWireVersion,omitempty" json:"min_wire_version,omitempty"`
	MaxBsonObjectSize            int32 `bson:"maxBsonObjectSize,omitempty" json:"max_bson_object_size,omitempty"`
	MaxWriteBatchSize            int32 `bson:"maxWriteBatchSize,omitempty" json:"max_write_batch_size,omitempty"`
	LogicalSessionTimeoutMinutes int32 `bson:"logicalSessionTimeoutMinutes,omitempty" json:"logical_session_timeout_minutes,omitempty"`
	MaxMessageSizeBytes          int32 `bson:"maxMessageSizeBytes,omitempty" json:"max_message_size_bytes,omitempty"`
	ReadOnly                     bool  `bson:"readOnly" json:"read_only"`
}

// Result holds the data returned by a scan
type Result struct {
	IsMaster  *IsMaster_t  `json:"is_master,omitempty"`
	BuildInfo *BuildInfo_t `json:"build_info,omitempty"`
}

// Init initializes the scanner
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.isMasterMsg = getIsMasterMsg()
	scanner.buildInfoCommandMsg = getBuildInfoQuery()
	scanner.buildInfoOpMsg = getBuildInfoOpMsg()
	return nil
}

// InitPerSender initializes the scanner for a given sender
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the name of the scanner
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "mongodb"
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Validate checks that the flags are valid
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string
func (flags *Flags) Help() string {
	return ""
}

// NewFlags provides an empty instance of the flags that will be filled in by the framework
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner provides a new scanner instance
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Perform a handshake with a MongoDB server"
}

// StartScan opens a connection to the target and sets up a scan instance for it.
func (scanner *Scanner) StartScan(target *zgrab2.ScanTarget) (*scan, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return nil, err
	}

	return &scan{
		target:  target,
		scanner: scanner,
		result:  &Result{},
		conn: &Connection{
			scanner: scanner,
			conn:    conn,
		},
		close: func() { conn.Close() },
	}, nil
}

// getIsMaster issues the isMaster command to the MongoDB server and returns the result.
func getIsMaster(conn *Connection) (*IsMaster_t, error) {
	document := &IsMaster_t{}
	doc_offset := MSGHEADER_LEN + 20
	conn.Write(conn.scanner.isMasterMsg)

	msg, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}

	if len(msg) < doc_offset+4 {
		err = fmt.Errorf("Server truncated message - no query reply (%d bytes: %s)", len(msg), hex.EncodeToString(msg))
		return nil, err
	}
	respFlags := binary.LittleEndian.Uint32(msg[MSGHEADER_LEN : MSGHEADER_LEN+4])
	if respFlags&QUERY_RESP_FAILED != 0 {
		err = fmt.Errorf("isMaster query failed")
		return nil, err
	}
	doclen := int(binary.LittleEndian.Uint32(msg[doc_offset : doc_offset+4]))
	if len(msg[doc_offset:]) < doclen {
		err = fmt.Errorf("Server truncated BSON reply doc (%d bytes: %s)",
			len(msg[doc_offset:]), hex.EncodeToString(msg))
		return nil, err
	}
	err = bson.Unmarshal(msg[doc_offset:], &document)
	if err != nil {
		err = fmt.Errorf("Server sent invalid BSON reply doc (%d bytes: %s)",
			len(msg[doc_offset:]), hex.EncodeToString(msg))
		return nil, err
	}
	return document, nil
}

// Scan connects to a host and performs a scan.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan, err := scanner.StartScan(&target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer scan.Close()

	result := scan.result
	result.IsMaster, err = getIsMaster(scan.conn)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}

	var query []byte
	var resplen_offset int
	var resp_offset int

	// See: https://github.com/mongodb/specifications/blob/master/source/message/OP_MSG.rst
	// "OP_MSG is only available in MongoDB 3.6 (maxWireVersion >= 6) and later."
	if result.IsMaster.MaxWireVersion < 6 {
		query = scanner.buildInfoCommandMsg
		resplen_offset = 4
		resp_offset = 20
	} else {
		query = scanner.buildInfoOpMsg
		resplen_offset = 5
		resp_offset = 5
	}

	scan.conn.Write(query)
	msg, err := scan.conn.ReadMsg()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &result, err
	}

	if len(msg) < MSGHEADER_LEN+resplen_offset {
		err = fmt.Errorf("Server truncated message - no metadata doc (%d bytes: %s)", len(msg), hex.EncodeToString(msg))
		return zgrab2.SCAN_PROTOCOL_ERROR, &result, err
	}

	responselen := int(binary.LittleEndian.Uint32(msg[MSGHEADER_LEN : MSGHEADER_LEN+resplen_offset]))
	if len(msg[MSGHEADER_LEN:]) < responselen {
		err = fmt.Errorf("Server truncated BSON response doc (%d bytes: %s)",
			len(msg[MSGHEADER_LEN:]), hex.EncodeToString(msg))
		return zgrab2.SCAN_PROTOCOL_ERROR, &result, err
	}
	bson.Unmarshal(msg[MSGHEADER_LEN+resp_offset:], &result.BuildInfo)

	return zgrab2.SCAN_SUCCESS, &result, err
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("mongodb", "mongodb", module.Description(), 27017, &module)
	if err != nil {
		log.Fatal(err)
	}
}
