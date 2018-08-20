package mongodb

import (
	"fmt"
	"encoding/hex"
	"encoding/binary"
	"github.com/zmap/zgrab2"
	log "github.com/sirupsen/logrus"
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
	config *Flags
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

// getCommandMsg returns a mongodb message containing the specified BSON-encoded command.
// metdata and commandArgs expected to be BSON byte arrays.
func getCommandMsg(database string, commandName string, metadata []byte, commandArgs []byte) ([]byte) {
	dblen := len(database) + 1
	cnlen := len(commandName) + 1
	mdlen := len(metadata)
	calen := len(commandArgs)

	msglen := MSGHEADER_LEN + dblen + cnlen + len(metadata) + len(commandArgs)
	out := make([]byte, msglen)
	// msg header
	binary.LittleEndian.PutUint32(out[0:], uint32(msglen))
	binary.LittleEndian.PutUint32(out[12:], OP_COMMAND)
	// command msg
	idx := MSGHEADER_LEN
	copy(out[idx:idx+dblen], []byte(database))
	idx += dblen
	copy(out[idx:idx+cnlen], []byte(commandName))
	idx += cnlen
	copy(out[idx:idx+mdlen], metadata)
	idx += mdlen
	copy(out[idx:idx+calen], commandArgs)
	return out
}

// getIsMasterMsg returns a mongodb message containing isMaster command.
// https://docs.mongodb.com/manual/reference/command/isMaster/
func getIsMasterMsg() ([]byte) {
	query, err := bson.Marshal(bson.M{ "isMaster": 1 })
	if err != nil {
		// programmer error
		panic("Invalid BSON")
	}
	query_msg := getOpQuery("admin.$cmd", query)
	return query_msg
}

// getBuildInfoCommandMsg returns a mongodb message containing a command to retrieve MongoDB build info.
func getBuildInfoCommandMsg() ([]byte) {
	metaData, err := bson.Marshal(bson.M{ "buildInfo": 1 })
	if err != nil {
		// programmer error
		panic("Invalid BSON")
	}
	commandArgs, err := bson.Marshal(bson.M{})
	if err != nil {
		// programmer error
		panic("Invalid BSON")
	}
	// "test" collection gleaned from tshark
	command_msg := getCommandMsg("test", "buildInfo", metaData, commandArgs)
	return command_msg
}

// getOpQuery returns a mongodb OP_QUERY message containing the specified BSON-encoded query.
// query expected to be BSON byte array.
func getOpQuery(collname string, query []byte) ([]byte) {
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
func getOpMsg(section []byte) ([]byte) {
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
func getBuildInfoOpMsg() ([]byte) {
	// gleaned from tshark
	section_payload, err := bson.Marshal(bson.M{ "buildinfo": 1, "$db": "admin" })
	if err != nil {
		// programmer error
		panic("Invalid BSON")
	}
	section := make([]byte, len(section_payload) + 1)
	copy(section[1:], section_payload)
	op_msg := getOpMsg(section)
	return op_msg
}

// BuildEnvironment_t holds build environment information returned by scan.
type BuildEnvironment_t struct {
	Distmod string `bson:"distmod,omitempty"`
	Distarch string `bson:"distarch,omitempty"`
	Cc string `bson:"cc,omitempty"`
	CcFlags string `bson:"ccflags,omitempty"`
	Cxx string `bson:"cxx,omitempty"`
	CxxFlags string `bson:"cxxflags,omitempty"`
	LinkFlags string `bson:"linkflags,omitempty"`
	TargetAarch string `bson:"target_arch,omitempty"`
	TargetOS string `bson:"target_os,omitempty"`
}

// Result holds the data returned by the scan
type Result struct {
	Version string `bson:"version,omitempty"`
	GitVersion string `bson:"gitVersion,omitempty"`
	BuildEnvironment BuildEnvironment_t `bson:"buildEnvironment,omitempty"`
}

// Init initializes the scanner
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
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

// GetPort returns the port being scanned
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
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

// IsMasterResult hold the result of an isMaster command. Currently,
// only interested in maxWireVersion.
type IsMasterResult struct {
	MaxWireVersion int32 `bson:"maxWireVersion"`
}

// getMaxWireVersion retrieves the maxWireVersion value reported by the MongoDB server.
func getMaxWireVersion(conn *Connection) (int32, error) {
	document := &IsMasterResult{}
	doc_offset := MSGHEADER_LEN + 20
	query := getIsMasterMsg()
	conn.Write(query)

	msg, err := conn.ReadMsg()
	if err != nil {
		return 0, err
	}

	if len(msg) < MSGHEADER_LEN + 4 {
		err = fmt.Errorf("Server truncated message - no query reply (%d bytes: %s)", len(msg), hex.EncodeToString(msg))
		return 0, err
	}
	respFlags := binary.LittleEndian.Uint32(msg[MSGHEADER_LEN:MSGHEADER_LEN + 5])
	if respFlags & QUERY_RESP_FAILED != 0 {
		err = fmt.Errorf("isMaster query failed")
		return 0, err
	}
	doclen := int(binary.LittleEndian.Uint32(msg[doc_offset:doc_offset + 4]))
	if len(msg[doc_offset:]) < doclen {
		err = fmt.Errorf("Server truncated BSON reply doc (%d bytes: %s)",
			  len(msg[doc_offset:]), hex.EncodeToString(msg))
		return 0, err
	}
	err = bson.Unmarshal(msg[doc_offset:], &document)
	if err != nil {
		err = fmt.Errorf("Server sent invalid BSON reply doc (%d bytes: %s)",
			  len(msg[doc_offset:]), hex.EncodeToString(msg))
		return 0, err
	}
	return document.MaxWireVersion, nil
}

// Scan connects to a host and performs a scan.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var status zgrab2.ScanStatus
	scan, err := scanner.StartScan(&target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer scan.Close()

	result := scan.result
	max_wirev, err := getMaxWireVersion(scan.conn)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}

	var query []byte
	var resplen_offset int
	var resp_offset int

	// Gleaned from wireshark - if "MaxWireVersion" is less than 7, then
	// "build info" command should be sent in an OP_COMMAND with the query sent
	// and response retrieved at "metadata" offset. At 7 and above, should 
	// be sent as an OP_MSG in the "section" field, and response is at "body" offset
	if max_wirev < 7 {
		query = getBuildInfoCommandMsg()
		resplen_offset = 4
		resp_offset = 0
	} else {
		query = getBuildInfoOpMsg()
		resplen_offset = 5
		resp_offset = 5
	}

	scan.conn.Write(query)
	msg, err := scan.conn.ReadMsg()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	if len(msg) < MSGHEADER_LEN + resplen_offset {
		err = fmt.Errorf("Server truncated message - no metadata doc (%d bytes: %s)", len(msg), hex.EncodeToString(msg))
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}

	responselen := int(binary.LittleEndian.Uint32(msg[MSGHEADER_LEN:MSGHEADER_LEN + resplen_offset]))
	if len(msg[MSGHEADER_LEN:]) < responselen {
		err =  fmt.Errorf("Server truncated BSON response doc (%d bytes: %s)",
				  len(msg[MSGHEADER_LEN:]), hex.EncodeToString(msg))
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	bson.Unmarshal(msg[MSGHEADER_LEN+resp_offset:], &result)

	return status, &result, err
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("mongodb", "mongodb", "Probe for mongodb", 27017, &module)
	if err != nil {
		log.Fatal(err)
	}
}
