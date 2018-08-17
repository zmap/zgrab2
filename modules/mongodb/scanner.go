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

// getBuildInfoMsg returns a mongodb message containing a command to retrieve MongoDB build info.
func getBuildInfoMsg() ([]byte) {
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
	query_msg := getCommandMsg("test", "buildInfo", metaData, commandArgs)
	return query_msg
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

// Scan connects to a host and performs a scan.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan, err := scanner.StartScan(&target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer scan.Close()

	result := scan.result

	// https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/
	// Issue " { buildInfo: 1 }" command.
	msg := getBuildInfoMsg()
	scan.conn.conn.Write(msg)

	binfo, err := scan.conn.ReadMsg()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if len(binfo) < MSGHEADER_LEN + 4 {
		err = fmt.Errorf("Server truncated message - no metadata doc (%d bytes: %s)", len(binfo), hex.EncodeToString(binfo))
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	// Seen in tshark - response returned in "metadata" position rather than "commandReply".
	// (not documented in mongodb wire protocol reference)
	metadatalen := int(binary.LittleEndian.Uint32(binfo[MSGHEADER_LEN:MSGHEADER_LEN + 4]))
	if len(binfo[MSGHEADER_LEN:]) < metadatalen {
		err =  fmt.Errorf("Server truncated BSON metadata doc (%d bytes: %s)",
				  len(binfo[MSGHEADER_LEN:]), hex.EncodeToString(binfo))
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	bson.Unmarshal(binfo[MSGHEADER_LEN:], &result)

	return zgrab2.SCAN_SUCCESS, &result, nil
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("mongodb", "mongodb", "Probe for mongodb", 27017, &module)
	if err != nil {
		log.Fatal(err)
	}
}
