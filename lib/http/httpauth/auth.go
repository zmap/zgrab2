package httpauth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/zmap/zgrab2/lib/http"
	log "github.com/sirupsen/logrus"
)

type Authenticator interface {
	TryGetAuth(req *http.Request, resp *http.Response) string
}

type digestAuthenticator map[string]*credential

// Map from hosts to credential pointers. Shouldn't be accessed directly.
type basicAuthenticator map[string]*credential

// TODO: Actually explain this.
type credential struct {
	Username, Password string
}

func NewDigestAuthenticator(credsFilename string, hostsToCreds map[string]string) (digestAuthenticator, error) {
	auther := make(digestAuthenticator)
	var err error
	// If a filename is given, record all {host, username:password} pairs it specifies.
	if credsFilename != "" {
		var fileHostsToCreds map[string]string
		// The only possible error here would result from os.Open on file.
		fileHostsToCreds, err = readCreds(credsFilename)
		auther.populate(fileHostsToCreds)
	}
	// If pairs are explicitly specified in a map[string]string, use them.
	// Override any pairs specified in a file with those specified in explicit map.
	if hostsToCreds != nil {
		auther.populate(hostsToCreds)
	}
	return auther, err
}

// TODO: Make sure that you can only specify one file? Maybe supporting multiple files makes sense.
func NewAuthenticator(credsFilename string, hostsToCreds map[string]string) (basicAuthenticator, error) {
	auther := make(basicAuthenticator)
	var err error
	// If a filename is given, record all {host, username:password} pairs it specifies.
	if credsFilename != "" {
		var fileHostsToCreds map[string]string
		// The only possible error here would result from os.Open on file.
		fileHostsToCreds, err = readCreds(credsFilename)
		auther.populate(fileHostsToCreds)
	}
	// If pairs are explicitly specified in a map[string]string, use them.
	// Override any pairs specified in a file with those specified in explicit map.
	if hostsToCreds != nil {
		auther.populate(hostsToCreds)
	}
	return auther, err
}

func readCreds(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		// TODO: Log with the correct logger and settle on a proper message for this. (ie: include filename)
		log.Warn("Couldn't open credentials file.")
		return nil, err
	}

	creds := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// TODO: Future: Add special case here for if the line starts with a character which has meaning in my planned grouping feature
		parts := strings.Split(line, " ")
		host := parts[0]
		// Preserve any spaces in username:password by combining everything after
		// first space (particularly because spaces are legal in Basic Auth passwords)
		var userpass string
		if len(parts) > 1 {
			userpass = strings.Join(parts[1:], " ")
		}
		creds[host] = userpass
	}
	return creds, nil
}

// TODO: Add quite a bit of parsing in order to one day support things like wildcards, IP ranges, etc.
// Though it's possible those are undesirable features because effective auth
// practices result in large swathes of machines NOT sharing credentials
// TODO: Should whether to use TLS be specified when setting up in the first place or for
// each particular instance? Either way, it only needs to be passed in once. It's
// really a matter of which makes more sense semantically.
// TODO: Determine whether an input that doesn't specify host should be assumed to default to all hosts
// Subsequent calls to populate (only made from NewAuthenticator) will, if possible,
// overwrite the result of previous calls.
func (credentials digestAuthenticator) populate(hostsToCreds map[string]string) {
	for host, userpass := range hostsToCreds {
		creds := strings.Split(userpass, ":")
		user := creds[0]
		// Preserve any colons in password by combining everything after first colon
		var pass string
		if len(creds) > 1 {
			pass = strings.Join(creds[1:], ":")
		}
		credentials[host] = &credential{Username: user, Password: pass}
	}
}

// TODO: Add quite a bit of parsing in order to one day support things like wildcards, IP ranges, etc.
	// Though it's possible those are undesirable features because effective auth
	// practices result in large swathes of machines NOT sharing credentials
// TODO: Should whether to use TLS be specified when setting up in the first place or for
	// each particular instance? Either way, it only needs to be passed in once. It's
	// really a matter of which makes more sense semantically.
// TODO: Determine whether an input that doesn't specify host should be assumed to default to all hosts
// Subsequent calls to populate (only made from NewAuthenticator) will, if possible,
// overwrite the result of previous calls.
func (credentials basicAuthenticator) populate(hostsToCreds map[string]string) {
	for host, userpass := range hostsToCreds {
		creds := strings.Split(userpass, ":")
		user := creds[0]
		// Preserve any colons in password by combining everything after first colon
		var pass string
		if len(creds) > 1 {
			pass = strings.Join(creds[1:], ":")
		}
		credentials[host] = &credential{Username: user, Password: pass}
	}
}

// TODO: Make the return type of this actually make any sense.
// TODO: Improve names because "parts" is silly. Maybe it's not though. Also params
func parseWwwAuth(header string) map[string]string {
	parameters := make(map[string]string)
	tokens := strings.Split(header, " ")
	//scheme := tokens[0]
	for _, token := range tokens[1:] {
		parts := strings.Split(token, "=")
		name := parts[0]
		var value string
		if len(parts) > 1 {
			value := parts[1]
			if value[len(value)-1:] == "," {
				value = value[:len(value)-1]
			}
		}
		parameters[name] = value
	}
	return parameters
}

func unquote(s string) string {
	// A string can only be quotes if it's at least two characters long.
	// TODO: Count runes instead of bytes, but this should be ASCII, so it shouldn't matter
	if len(s) >= 2 {
		if s[:1] == `"` && s[len(s)-1:] == `"` {
			s = s[1:len(s)-1]
		}
		// TODO: Determine if any other escaping needs to be undone. I don't think so, since double-quotes are the relevant problem.
		s = strings.Replace(s, `\"`, `"`, -1)
	}
	return s
}

func getHost(req *http.Request) string {
	// TODO: Consider whether taking in https status would be a good precaution,
		// in order to somehow warn about plaintext auth or implement safer defaults
	// TODO: Take in either a target or just a host string as appropriate?
	//host := t.Domain
	//if host == "" {
	//	host = t.IP.String()
	//}
	// TODO: Figure out a good way to get the IP address involved in an http request
		// Otherwise, require the caller pass in the relevant hostname/ip
	// If both are accepted, could list different creds for IP and hostname.
		// Unclear how to resolve that conflict.
	host := req.Host
	if strings.Contains(host, ":") {
		// Removes the port (after final colon) from hostname in order to match the
		// format used in credentials's keys. If present, : is separating port from host.
		parts := strings.Split(host, ":")
		host = strings.Join(parts[:len(parts)-1], ":")
	}
	return host
}

func keyedDigest(h func(string) string, secret, data string) (hash string) {
	return h(secret + ":" + data)
}

// TODO: Leverage hashing algorithms from crypto library
var algorithms map[string]func(string) string = map[string]func(string) string{
	"MD5": func(s string) string {
		// TODO: Implement
		return s
	},
	"SHA-256": func(s string) string {
		// TODO: Implement
		return s
	},
	"SHA-512-256": func(s string) string {
		// TODO: Implement
		return s
	},
}

// TODO: This function totally needs to be split up into constituent parts.
// TODO: Determine whether these args need to be pointers at all? Efficiency is a real contributor to that.
// TODO: Figure out whether a method signature that doesn't rely on http for types is better or more versatile
func (credentials digestAuthenticator) TryGetAuth(req *http.Request, resp *http.Response) string {
	// Return quickly in the case that Authorization header can't be constructed
	if resp == nil || resp.Header == nil {
		return ""
	}

	return ""
}

// TODO: Determine whether these args need to be pointers at all? Efficiency is a real contributor to that.
// TODO: Figure out whether a method signature that doesn't rely on http for types is better or more versatile
func (credentials basicAuthenticator) TryGetAuth(req *http.Request, resp *http.Response) string {
	host := getHost(req)
	// Explicitly declare Header so that it's a non-nil map that can be assigned to in .SetBasicAuth
	temp := &http.Request{Header: make(http.Header)}
	// TODO: Maybe act differently if host is empty
	creds, ok := credentials[host]
	if ok {
		temp.SetBasicAuth(creds.Username, creds.Password)
	}
	// TODO: Otherwise, assign default creds if those are specified

	return temp.Header.Get("Authorization")
}

// TODO: Handle discrepencies between hostname and ip address
// Should probably be resolved by a DNS lookup? Or maybe mandate all input be IP's.