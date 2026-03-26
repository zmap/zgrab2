package ldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the LDAP scanner.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// UseLDAPS enables implicit TLS (LDAPS, typically port 636).
	UseLDAPS bool `long:"ldaps" description:"Use LDAPS (implicit TLS, typically port 636)"`

	// UseStartTLS forces a STARTTLS upgrade before querying the Root DSE.
	UseStartTLS bool `long:"starttls" description:"Force STARTTLS before querying the Root DSE"`

	// NoSTARTTLSAuto disables automatic STARTTLS detection and upgrade.
	// By default, the scanner queries the Root DSE over plaintext first and
	// automatically upgrades via STARTTLS if the server advertises support
	// (OID 1.3.6.1.4.1.1466.20037 in supportedExtension). Use this flag to
	// skip that auto-upgrade and return only the plaintext results.
	NoSTARTTLSAuto bool `long:"no-starttls-auto" description:"Disable automatic STARTTLS upgrade when the server advertises support"`
}

// Scanner implements the zgrab2.Scanner interface for LDAP.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// ScanResults contains the output of an LDAP Root DSE scan.
type ScanResults struct {
	// RootDSE contains all attributes returned by the Root DSE query, organized into typed fields.
	SupportedLDAPVersion    []string `json:"supported_ldap_version,omitempty"`
	SupportedExtension      []string `json:"supported_extension,omitempty"`
	SupportedControl        []string `json:"supported_control,omitempty"`
	SupportedCapabilities   []string `json:"supported_capabilities,omitempty"`
	SupportedSASLMechanisms []string `json:"supported_sasl_mechanisms,omitempty"`
	SupportedLDAPPolicies   []string `json:"supported_ldap_policies,omitempty"`
	NamingContexts          []string `json:"naming_contexts,omitempty"`

	SubschemaSubentry             string `json:"subschema_subentry,omitempty"`
	ServerName                    string `json:"server_name,omitempty"`
	SchemaNamingContext           string `json:"schema_naming_context,omitempty"`
	RootDomainNamingContext       string `json:"root_domain_naming_context,omitempty"`
	LDAPServiceName               string `json:"ldap_service_name,omitempty"`
	IsSynchronized                string `json:"is_synchronized,omitempty"`
	IsGlobalCatalogReady          string `json:"is_global_catalog_ready,omitempty"`
	HighestCommittedUSN           string `json:"highest_committed_usn,omitempty"`
	ForestFunctionality           string `json:"forest_functionality,omitempty"`
	DsServiceName                 string `json:"ds_service_name,omitempty"`
	DomainFunctionality           string `json:"domain_functionality,omitempty"`
	DomainControllerFunctionality string `json:"domain_controller_functionality,omitempty"`
	DNSHostName                   string `json:"dns_host_name,omitempty"`
	DefaultNamingContext          string `json:"default_naming_context,omitempty"`
	CurrentTime                   string `json:"current_time,omitempty"`
	ConfigurationNamingContext    string `json:"configuration_naming_context,omitempty"`

	// OtherAttributes captures any Root DSE attributes not covered by the typed fields above.
	OtherAttributes map[string][]string `json:"other_attributes,omitempty"`

	// TLSLog contains the TLS handshake log if TLS was used.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`

	// StartTLSResponse is the result code from the STARTTLS extended operation (if used).
	StartTLSResponse *int64 `json:"starttls_response,omitempty"`
}

// NewModule returns a new LDAP module.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"ldap",
		"LDAP",
		"Perform an LDAP Root DSE search to collect server metadata, supported extensions, controls, and capabilities.",
		389,
	)
}

func (f Flags) Validate(_ []string) error {
	if f.UseLDAPS && f.UseStartTLS {
		return errors.New("cannot use both --ldaps and --starttls")
	}
	if f.UseLDAPS && f.NoSTARTTLSAuto {
		return errors.New("--no-starttls-auto has no effect with --ldaps")
	}
	if f.UseStartTLS && f.NoSTARTTLSAuto {
		return errors.New("--no-starttls-auto has no effect with --starttls")
	}
	return nil
}

func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)

	// Always enable TLS infrastructure so the TLSWrapper is available for
	// auto-detected STARTTLS upgrades, not just explicit --ldaps/--starttls.
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

// Scan connects to the target, performs an LDAP Root DSE search, and optionally
// upgrades to TLS. The default behavior queries the Root DSE over plaintext first,
// then automatically upgrades via STARTTLS if the server advertises support.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found; LDAP requires an L4 dialer")
	}
	if dialGroup.TLSWrapper == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("TLS wrapper not available")
	}

	// Establish TCP connection
	addr := net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port)))
	conn, err := l4Dialer(target)(ctx, "tcp", addr)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error connecting to %s: %w", addr, err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	result := &ScanResults{}

	// LDAPS: wrap the entire connection in TLS immediately, then do Root DSE search
	if scanner.config.UseLDAPS {
		tlsConn, err := dialGroup.TLSWrapper(ctx, target, conn)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("TLS handshake failed: %w", err)
		}
		result.TLSLog = tlsConn.GetLog()
		conn = tlsConn

		if err := scanner.searchRootDSE(conn, result); err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		return zgrab2.SCAN_SUCCESS, result, nil
	}

	// Forced STARTTLS: upgrade before querying
	if scanner.config.UseStartTLS {
		if err := scanner.doStartTLS(conn, result); err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		tlsConn, err := dialGroup.TLSWrapper(ctx, target, conn)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("TLS handshake after STARTTLS failed: %w", err)
		}
		result.TLSLog = tlsConn.GetLog()
		conn = tlsConn

		if err := scanner.searchRootDSE(conn, result); err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		return zgrab2.SCAN_SUCCESS, result, nil
	}

	// Default mode: query Root DSE first over plaintext, then auto-upgrade if supported
	if err := scanner.searchRootDSE(conn, result); err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}

	// Check if the server advertises STARTTLS support and auto-upgrade
	if !scanner.config.NoSTARTTLSAuto && serverSupportsStartTLS(result) {
		log.Debug("server advertises STARTTLS support, auto-upgrading")
		if err := scanner.doStartTLS(conn, result); err != nil {
			// STARTTLS failed, but we already have the plaintext results
			log.Debugf("auto STARTTLS upgrade failed: %v", err)
			return zgrab2.SCAN_SUCCESS, result, nil
		}
		tlsConn, err := dialGroup.TLSWrapper(ctx, target, conn)
		if err != nil {
			log.Debugf("TLS handshake after auto STARTTLS failed: %v", err)
			return zgrab2.SCAN_SUCCESS, result, nil
		}
		result.TLSLog = tlsConn.GetLog()
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}

// serverSupportsStartTLS checks if the Root DSE supportedExtension list contains the STARTTLS OID.
func serverSupportsStartTLS(result *ScanResults) bool {
	for _, oid := range result.SupportedExtension {
		if oid == OIDStartTLS {
			return true
		}
	}
	return false
}

// doStartTLS sends the LDAP STARTTLS extended request and reads the response.
func (scanner *Scanner) doStartTLS(conn net.Conn, result *ScanResults) error {
	startTLSReq := buildExtendedRequest(1, OIDStartTLS)
	_, err := conn.Write(startTLSReq.Bytes())
	if err != nil {
		return fmt.Errorf("error sending STARTTLS request: %w", err)
	}

	// Read the ExtendedResponse
	resp, err := readLDAPMessage(conn)
	if err != nil {
		return fmt.Errorf("error reading STARTTLS response: %w", err)
	}

	tag := getMessageTag(resp)
	if tag != ApplicationExtendedResponse {
		return fmt.Errorf("expected ExtendedResponse (tag %d), got tag %d", ApplicationExtendedResponse, tag)
	}

	resultCode, err := getResultCode(resp)
	if err != nil {
		return fmt.Errorf("error parsing STARTTLS result code: %w", err)
	}
	result.StartTLSResponse = &resultCode

	if resultCode != 0 {
		return fmt.Errorf("STARTTLS failed with result code %d", resultCode)
	}

	return nil
}

// searchRootDSE sends a SearchRequest for the Root DSE and populates the results.
func (scanner *Scanner) searchRootDSE(conn net.Conn, result *ScanResults) error {
	// Use messageID=2 (or 1 if no STARTTLS was sent, but 2 is safe regardless)
	messageID := int64(2)
	searchReq := buildSearchRequest(messageID)

	_, err := conn.Write(searchReq.Bytes())
	if err != nil {
		return fmt.Errorf("error sending Root DSE search request: %w", err)
	}

	// Read responses until we get SearchResultDone
	for {
		resp, err := readLDAPMessage(conn)
		if err != nil {
			return fmt.Errorf("error reading search response: %w", err)
		}

		tag := getMessageTag(resp)
		switch tag {
		case ApplicationSearchResultEntry:
			attrs, err := parseSearchResultEntry(resp)
			if err != nil {
				return fmt.Errorf("error parsing SearchResultEntry: %w", err)
			}
			populateResults(result, attrs)

		case ApplicationSearchResultDone:
			resultCode, err := getResultCode(resp)
			if err != nil {
				return fmt.Errorf("error parsing SearchResultDone: %w", err)
			}
			if resultCode != 0 {
				return fmt.Errorf("root DSE search failed with result code %d", resultCode)
			}
			return nil

		default:
			// Unexpected message type; log and continue
			log.Debugf("unexpected LDAP message tag %d during Root DSE search", tag)
		}
	}
}

// firstOrEmpty returns the first element of a slice or empty string.
func firstOrEmpty(vals []string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// populateResults maps Root DSE attributes into the typed ScanResults fields.
func populateResults(result *ScanResults, attrs map[string][]string) {
	// Known multi-valued attributes
	knownMulti := map[string]*[]string{
		"supportedLDAPVersion":    &result.SupportedLDAPVersion,
		"supportedExtension":      &result.SupportedExtension,
		"supportedControl":        &result.SupportedControl,
		"supportedCapabilities":   &result.SupportedCapabilities,
		"supportedSASLMechanisms": &result.SupportedSASLMechanisms,
		"supportedLDAPPolicies":   &result.SupportedLDAPPolicies,
		"namingContexts":          &result.NamingContexts,
	}

	// Known single-valued attributes
	knownSingle := map[string]*string{
		"subschemaSubentry":             &result.SubschemaSubentry,
		"serverName":                    &result.ServerName,
		"schemaNamingContext":           &result.SchemaNamingContext,
		"rootDomainNamingContext":       &result.RootDomainNamingContext,
		"ldapServiceName":               &result.LDAPServiceName,
		"isSynchronized":                &result.IsSynchronized,
		"isGlobalCatalogReady":          &result.IsGlobalCatalogReady,
		"highestCommittedUSN":           &result.HighestCommittedUSN,
		"forestFunctionality":           &result.ForestFunctionality,
		"dsServiceName":                 &result.DsServiceName,
		"domainFunctionality":           &result.DomainFunctionality,
		"domainControllerFunctionality": &result.DomainControllerFunctionality,
		"dnsHostName":                   &result.DNSHostName,
		"defaultNamingContext":          &result.DefaultNamingContext,
		"currentTime":                   &result.CurrentTime,
		"configurationNamingContext":    &result.ConfigurationNamingContext,
	}

	for name, values := range attrs {
		if dest, ok := knownMulti[name]; ok {
			*dest = values
			continue
		}
		if dest, ok := knownSingle[name]; ok {
			*dest = firstOrEmpty(values)
			continue
		}
		// Unknown attribute → store in OtherAttributes
		if result.OtherAttributes == nil {
			result.OtherAttributes = make(map[string][]string)
		}
		result.OtherAttributes[name] = values
	}
}
