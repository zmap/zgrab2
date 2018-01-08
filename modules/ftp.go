package modules

import (
	"net"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// FTPScanResults is the output of the scan. Identical to the original from zgrab, with the addition of TLSLog.
type FTPScanResults struct {
	Banner      string         `json:"banner,omitempty"`
	AuthTLSResp string         `json:"auth_tls_resp,omitempty"`
	AuthSSLResp string         `json:"auth_ssl_resp,omitempty"`
	TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

// FTP-specific command-line flags. Taken from the original zgrab (TODO: should FTPAuthTLS be on by default?).
type FTPFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Verbose    bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	FTPAuthTLS bool `long:"authtls" description:"Collect FTPS certificates in addition to FTP banners"`
}

// FTPModule implements the zgrab2.Module interface
type FTPModule struct {
}

// FTPScanner implements the zgrab2.Scanner interface, and holds the state for a single scan instance
type FTPScanner struct {
	config *FTPFlags
}

// FTPConnection holds the state for a single connection to the FTP server.
type FTPConnection struct {
	buffer  [1024]byte // temp buffer for sending commands -- so, never interleave sendCommand calls on a given connection
	config  *FTPFlags
	results FTPScanResults
	conn    net.Conn
}

// ftp.init() registers the ftp zgrab2 module
func init() {
	var module FTPModule
	_, err := zgrab2.AddCommand("ftp", "FTP", "Grab a FTP banner", 21, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *FTPModule) NewFlags() interface{} {
	return new(FTPFlags)
}

func (m *FTPModule) NewScanner() zgrab2.Scanner {
	return new(FTPScanner)
}

func (f *FTPFlags) Validate(args []string) error {
	return nil
}

func (f *FTPFlags) Help() string {
	return ""
}

func (s *FTPScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*FTPFlags)
	s.config = f
	return nil
}

func (s *FTPScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *FTPScanner) GetName() string {
	return s.config.Name
}

func (s *FTPScanner) GetPort() uint {
	return s.config.Port
}

// ftpEndRegex matches zero or more lines followed by a numeric FTP status code and linebreak, e.g. "200 OK\r\n"
var ftpEndRegex = regexp.MustCompile(`^(?:.*\r?\n)*([0-9]{3})( [^\r\n]*)?\r?\n$`)

// FTPConnection.isOKResponse() returns true iff the given response code indicates success (e.g. 2XX)
func (ftp *FTPConnection) isOKResponse(retCode string) bool {
	// TODO: This is the current behavior; should it check that it isn't garbage that happens to start with 2 (e.g. it's only ASCII chars, the prefix is 2[0-9]+, etc)?
	return strings.HasPrefix(retCode, "2")
}

// FTPConnection.readResponse() reads an FTP response chunk from the server. It returns the full response, as well as the status code alone.
func (ftp *FTPConnection) readResponse() (string, string, error) {
	respLen, err := zgrab2.ReadUntilRegex(ftp.conn, ftp.buffer[:], ftpEndRegex)
	if err != nil {
		return "", "", err
	}
	ret := string(ftp.buffer[0:respLen])
	retCode := ftpEndRegex.FindStringSubmatch(ret)[1]
	return ret, retCode, nil
}

// FTPConnection.GetFTPBanner() was taken over from the original zgrab. Read the banner sent by the server immediately after connecting. Returns true iff the server returns a succesful status code.
func (ftp *FTPConnection) GetFTPBanner() (bool, error) {
	banner, retCode, err := ftp.readResponse()
	if err != nil {
		return false, err
	}
	ftp.results.Banner = banner
	return ftp.isOKResponse(retCode), nil
}

// FTPConnection.sendCommand() sends a command to the server and waits for / reads / returns the response.
func (ftp *FTPConnection) sendCommand(cmd string) (string, string, error) {
	ftp.conn.Write([]byte(cmd + "\r\n"))
	return ftp.readResponse()
}

// FTPConnection.SetupFTPS() was taken over from the original zgrab. Returns true iff the server reported support for FTPS. First attempt AUTH TLS; if that fails, try AUTH SSL.
func (ftp *FTPConnection) SetupFTPS() (bool, error) {
	ret, retCode, err := ftp.sendCommand("AUTH TLS")
	if err != nil {
		return false, err
	}
	ftp.results.AuthTLSResp = ret
	if ftp.isOKResponse(retCode) {
		return true, nil
	} else {
		ret, retCode, err = ftp.sendCommand("AUTH SSL")
		if err != nil {
			return false, err
		}
		ftp.results.AuthSSLResp = ret

		if ftp.isOKResponse(retCode) {
			return true, nil
		}
		return false, nil
	}
}

// FTPConnection.GetFTPSCertificates() was taken over from the original zgrab. If the server supports TLS/SSL, perform the handshake. The connection's results field is populated with the results.
func (ftp *FTPConnection) GetFTPSCertificates() error {
	ftpsReady, err := ftp.SetupFTPS()

	if err != nil {
		return err
	}
	if !ftpsReady {
		return nil
	}
	var conn *zgrab2.TLSConnection
	if conn, err = ftp.config.TLSFlags.GetTLSConnection(ftp.conn); err != nil {
		return err
	}
	ftp.results.TLSLog = conn.GetLog()

	if err = conn.Handshake(); err != nil {
		// NOTE: With the default config of vsftp (without ssl_ciphers=HIGH), AUTH TLS succeeds, but the handshake fails, dumping "error:1408A0C1:SSL routines:ssl3_get_client_hello:no shared cipher" to the socket.
		return err
	}
	ftp.conn = conn
	return nil
}

// FTPScanner.Scan() was taken over from the original zgrab. Reads the initial banner, then, if FTPAuthTLS is set, attempt an upgrade to FTPS.
func (s *FTPScanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	var err error
	conn, err := t.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	ftp := FTPConnection{conn: conn, config: s.config, results: FTPScanResults{}}
	is200Banner, err := ftp.GetFTPBanner()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &ftp.results, err
	}
	if s.config.FTPAuthTLS && is200Banner {
		if err := ftp.GetFTPSCertificates(); err != nil {
			return zgrab2.SCAN_APPLICATION_ERROR, &ftp.results, err
		}
	}
	return zgrab2.SCAN_SUCCESS, &ftp.results, nil
}
