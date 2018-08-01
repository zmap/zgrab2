package httpauth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/zmap/zgrab2/lib/http"
	log "github.com/sirupsen/logrus"
)

var credentials map[string]*credential = make(map[string]*credential)

// TODO: Actually explain this.
type credential struct {
	Username, Password string
}

func ReadFile(filename string) (*map[string]string, error) {
	result := make(map[string]string)
	file, err := os.Open(filename)
	if err != nil {
		// TODO: Make an actual error message for this.
		log.Warn("Couldn't open credentials file.")
		return nil, err
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// TODO: Add special case here for if the line starts with a character
		// which has meaning for my planned group feature's semantics
		parts := strings.Split(line, " ")
		host := parts[0]
		var userpass string
		if len(parts) > 1 {
			userpass = strings.Join(parts[1:], " ")
		}
		result[host] = userpass
	}
	return &result, nil
}

// TODO: Add quite a bit of parsing in order to one day support things like wildcards, IP ranges, etc.
	// Though it's possible those are undesirable features because effective auth
	// practices result in large swathes of machines NOT sharing credentials
// TODO: Should HTTPS-use (or doom) be specified when setting up in the first place or for
	// each particular instance? Either way, it only needs to be passed in once. It's
	// really a matter of which makes more sense semantically.
// TODO: Determine whether an input that doesn't specify host should be assumed to default to all hosts
// TODO: Determine whether preparing based on file flag or command line options should take precedence
func Prepare(mapping *map[string]string) {
	if mapping == nil {
		// TODO: Log an actual error here
		log.Warn("Passed in nil map to Prepare.")
		return
	}
	if *mapping == nil {
		*mapping = make(map[string]string)
	}
	for host, userpass := range *mapping {
		creds := strings.Split(userpass, ":")
		user := creds[0]
		var pass string
		if len(creds) > 1 {
			pass = strings.Join(creds[1:], ":")
		}
		credentials[host] = &credential{Username: user, Password: pass}
	}
	// TODO: Remove this after I'm done writing the thing.
	fmt.Printf("%q\n", credentials)
}

// TODO: Add a notion of whether to try to authenticate or not (to allow for hosts
// that can't support auth), but maybe no auth ignores credentials just fine.
// Sets auth if appropriate
func TrySetAuth(req *http.Request) {
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

// Discrepencies between hostname and ip address
// Should probably be resolved by a DNS lookup? Or maybe mandate all input be IP's.