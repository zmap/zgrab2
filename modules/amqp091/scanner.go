package amqp091

import (
	"fmt"

	"encoding/json"

	amqpLib "github.com/rabbitmq/amqp091-go"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the smb scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags

	Vhost    string `long:"vhost" description:"The vhost to connect to" default:"/"`
	AuthUser string `long:"auth-user" description:"Username to use for authentication. Must be used with --auth-pass. No auth is attempted if not provided."`
	AuthPass string `long:"auth-pass" description:"Password to use for authentication. Must be used with --auth-user. No auth is attempted if not provided."`

	UseTLS bool `long:"use-tls" description:"Use TLS to connect to the server. Note that AMQPS uses a different default port (5671) than AMQP (5672) and you will need to specify that port manually with -p."`
	zgrab2.TLSFlags
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type connectionTune struct {
	ChannelMax int `json:"channel_max"`
	FrameMax   int `json:"frame_max"`
	Heartbeat  int `json:"heartbeat"`
}

// https://www.rabbitmq.com/amqp-0-9-1-reference#connection.start.server-properties
type knownServerProperties struct {
	Product      string `json:"product"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Copyright    string `json:"copyright"`
	Information  string `json:"information"`
	UnknownProps string `json:"unknown_props"`
}

// copy known properties, and store unknown properties in serialized json string
// if known properties are not found, set fields to empty strings
func (p *knownServerProperties) populate(props amqpLib.Table) {
	if product, ok := props["product"].(string); ok {
		p.Product = product
		delete(props, "product")
	}
	if version, ok := props["version"].(string); ok {
		p.Version = version
		delete(props, "version")
	}
	if platform, ok := props["platform"].(string); ok {
		p.Platform = platform
		delete(props, "platform")
	}
	if copyright, ok := props["copyright"].(string); ok {
		p.Copyright = copyright
		delete(props, "copyright")
	}
	if information, ok := props["information"].(string); ok {
		p.Information = information
		delete(props, "information")
	}

	if unknownProps, err := json.Marshal(props); err == nil {
		p.UnknownProps = string(unknownProps)
	}
}

type Result struct {
	Failure string `json:"failure"`

	VersionMajor     int                   `json:"version_major"`
	VersionMinor     int                   `json:"version_minor"`
	ServerProperties knownServerProperties `json:"server_properties"`
	Locales          []string              `json:"locales"`

	AuthSuccess bool `json:"auth_success"`

	Tune *connectionTune `json:"tune,omitempty"`

	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("amqp091", "amqp091", module.Description(), 5672, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for Advanced Message Queuing Protocol 0.9.1 servers"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	if flags.AuthUser != "" && flags.AuthPass == "" {
		return fmt.Errorf("must provide --auth-pass if --auth-user is set")
	}
	if flags.AuthPass != "" && flags.AuthUser == "" {
		return fmt.Errorf("must provide --auth-user if --auth-pass is set")
	}
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*Flags)
	if !ok {
		return fmt.Errorf("failed to cast flags to AMQP flags")
	}

	scanner.config = f
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
	return "amqp091"
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// Setup result and connection cleanup
	result := &Result{
		AuthSuccess: false,
	}
	var tlsConn *zgrab2.TLSConnection
	defer func() {
		conn.Close()

		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
	}()

	// If we're using TLS, wrap the connection
	if scanner.config.UseTLS {
		tlsConn, err = scanner.config.TLSFlags.GetTLSConnection(conn)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		if err := tlsConn.Handshake(); err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		conn = tlsConn
	}

	// Prepare AMQP connection config
	config := amqpLib.Config{
		Vhost:      scanner.config.Vhost,
		ChannelMax: 0,
		FrameSize:  0,
		Heartbeat:  0,
	}

	// If we have auth credentials, set up PLAIN SASL
	if scanner.config.AuthUser != "" && scanner.config.AuthPass != "" {
		config.SASL = []amqpLib.Authentication{
			&amqpLib.PlainAuth{
				Username: scanner.config.AuthUser,
				Password: scanner.config.AuthPass,
			},
		}
	}

	// Open the AMQP connection
	amqpConn, err := amqpLib.Open(conn, config)
	if err != nil {
		result.Failure = err.Error()
	}
	defer amqpConn.Close()

	// If there's an error and we haven't even received START frame from the server, consider it a failure
	if err != nil && len(amqpConn.Locales) == 0 {
		status := zgrab2.TryGetScanStatus(err)
		if status == zgrab2.SCAN_UNKNOWN_ERROR {
			// Consider this a protocol error if it's not any of the known network errors
			status = zgrab2.SCAN_PROTOCOL_ERROR
		}

		return status, nil, err
	}
	// If amqpConn.Locales has sth, we are (almost) sure that we are talking to an AMQP 091 server,
	// therefore the scan is considered successful from this point on.

	// Following is basic server information that can be gathered without authentication
	result.VersionMajor = amqpConn.Major
	result.VersionMinor = amqpConn.Minor
	result.Locales = amqpConn.Locales
	result.ServerProperties.populate(amqpConn.Properties)

	// Heuristic to see if we're authenticated.
	// These values are expected to be non-zero if and only if a tune is received and we're authenticated.
	if err != amqpLib.ErrSASL && err != amqpLib.ErrCredentials && amqpConn.Config.ChannelMax > 0 {
		result.AuthSuccess = true
		result.Tune = &connectionTune{
			ChannelMax: amqpConn.Config.ChannelMax,
			FrameMax:   amqpConn.Config.FrameSize,
			Heartbeat:  int(amqpConn.Config.Heartbeat.Seconds()),
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
