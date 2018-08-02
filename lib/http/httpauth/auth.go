package httpauth

import (
	"bufio"
	//"fmt"
	"os"
	"strings"

	"github.com/zmap/zgrab2/lib/http"
	log "github.com/sirupsen/logrus"
)

type Authenticator interface {
	TrySetAuth(req *http.Request)
}

// Map from hosts to credential pointers. Shouldn't be accessed directly.
type authenticator map[string]*credential

// TODO: Actually explain this.
type credential struct {
	Username, Password string
}

// TODO: Determine whether comments should reference command line arguments,
//       since this should be abstracted from that application of this package.
// TODO: Make sure that you can only specify one file? Maybe supporting multiple files makes sense.
func NewAuthenticator(credsFilename *string, hostsToCreds *map[string]string) (*authenticator, error) {
	auther := make(authenticator)
	var err error
	// If a filename is given, record all {host, username:password} pairs it specifies.
	if credsFilename != nil {
		var fileHostsToCreds *map[string]string
		// The only possible error here would result from os.Open on file.
		fileHostsToCreds, err = readCreds(*credsFilename)
		auther.populate(fileHostsToCreds)
	}
	// If pairs are explicitly specified as map[string]string, use them.
	// Override any pairs specified in a file with those specified in explicit map.
	if hostsToCreds != nil {
		auther.populate(hostsToCreds)
	}
	return &auther, err
}

func readCreds(filename string) (*map[string]string, error) {
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
	return &creds, nil
}

// TODO: Add quite a bit of parsing in order to one day support things like wildcards, IP ranges, etc.
	// Though it's possible those are undesirable features because effective auth
	// practices result in large swathes of machines NOT sharing credentials
// TODO: Should HTTPS-use (or doom) be specified when setting up in the first place or for
	// each particular instance? Either way, it only needs to be passed in once. It's
	// really a matter of which makes more sense semantically.
// TODO: Determine whether an input that doesn't specify host should be assumed to default to all hosts
// TODO: Determine whether preparing based on file flag or command line options should take precedence
func (credentials authenticator) populate(hostsToCreds *map[string]string) {
	if hostsToCreds == nil {
		// TODO: Or just silently do nothing
		// TODO: Return an actual error here
		//log.Warn("Passed in nil map to prepare.")
		return
	}
	if *hostsToCreds == nil {
		*hostsToCreds = make(map[string]string)
	}
	for host, userpass := range *hostsToCreds {
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

// TODO: Add a notion of whether to try to authenticate or not (to allow for hosts
// that can't support auth), but maybe no auth ignores credentials just fine.
// Sets auth if appropriate
func (credentials authenticator) TrySetAuth(req *http.Request) {
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
	// Removes the port (after final colon) from the hostname in order to match the
	// format used in the package-global map, "credentials"
	parts := strings.Split(req.Host, ":")
	hostname := strings.Join(parts[:len(parts)-1], ":")
	// TODO: Maybe act differently if host is empty
	creds, ok := credentials[hostname]
	if ok {
		req.SetBasicAuth(creds.Username, creds.Password)
	}
	// TODO: Otherwise, assign default creds if those are specified
}

// TODO: Handle discrepencies between hostname and ip address
// Should probably be resolved by a DNS lookup? Or maybe mandate all input be IP's.