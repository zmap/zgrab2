package httpauth

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/zmap/zgrab2/lib/http"
	log "github.com/sirupsen/logrus"
)

type Authenticator interface {
	TryGetAuth(req *http.Request, resp *http.Response) string
}

// TODO: Make this contain state useful for constructing a next response (ie: nextnonce field)
// TODO: Session state ("-sess") could also be handy here, since it persists from one request to the next.
	// Though that might also be wrong, since this object should persist while connecting to one host or another.
// TODO: Similarly, maintaining nonce counter presents some interesting challenges. Maybe more state per-host makes sense.
type authenticator struct {
	// Map from hosts to credential pointers. Shouldn't be accessed directly.
	creds map[string]*credential
}

// TODO: Actually explain this.
type credential struct {
	Username, Password string
}

// TODO: Make sure that you can only specify one file? Maybe supporting multiple files makes sense.
func NewAuthenticator(credsFilename string, hostsToCreds map[string]string) (authenticator, error) {
	auther := authenticator{creds: make(map[string]*credential)}
	var err error
	// If a filename is given, record all {host, username:password} pairs it specifies.
	if credsFilename != "" {
		var fileHostsToCreds map[string]string
		// The only possible error here would result from os.Open on file.
		fileHostsToCreds, err = readCreds(credsFilename)
		populate(auther, fileHostsToCreds)
	}
	// If pairs are explicitly specified in a map[string]string, use them.
	// Override any pairs specified in a file with those specified in explicit map.
	if hostsToCreds != nil {
		populate(auther, hostsToCreds)
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
func populate(result authenticator, hostsToCreds map[string]string) {
	for host, userpass := range hostsToCreds {
		creds := strings.Split(userpass, ":")
		user := creds[0]
		// Preserve any colons in password by combining everything after first colon
		var pass string
		if len(creds) > 1 {
			pass = strings.Join(creds[1:], ":")
		}
		result.creds[host] = &credential{Username: user, Password: pass}
	}
}

// TODO: Improve names because "token" is inaccurate and "parts" imprecise. Same goes for "chunk".
func parseWwwAuth(header string) map[string]string {
	var inQuotes bool
	var tokens []string
	var chunk []rune
	for i, c := range header {
		if c == '=' && !inQuotes {
			tokens = append(tokens, string(chunk))
			chunk = chunk[:0]
			continue
		}
		// TODO: This might be insufficient if you had the sequence `\\"`, but it's not
		// clear to me whether slashes are generally escaped in this context
		// This assumes that the first character of Www-Authenticate header is not
		// `"`, which should hold for any extant scheme.
		if c == '"' && header[i - 1] == '\\' {
			inQuotes = !inQuotes
		}
		chunk = append(chunk, c)
	}
	tokens = append(tokens, string(chunk))

	parameters := make(map[string]string)
	for i, token := range tokens[1:] {
		prevParts := strings.Split(tokens[i], " ")
		name := prevParts[len(prevParts)-1]
		var value string
		if token[:1] == `"` {
			parts := strings.Split(token, `"`)
			value = strings.Join(parts[:len(parts)-1], `"`) + `"`
		} else {
			parts := strings.Split(token, " ")
			if len(parts) > 1 {
				value = strings.Join(parts[:len(parts)-1], " ")
			}
			value = parts[0]
		}
		if value[len(value)-1:] == "," {
			value = value[:len(value)-1]
		}
		parameters[name] = value
	}

	return parameters
}

func unquote(s string) string {
	// A string can only be in quotes if it's at least two characters long.
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
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

var algorithms map[string]func(string) string = map[string]func(string) string{
	"MD5": func(s string) string {
		return fmt.Sprintf("%x", md5.Sum([]byte(s)))
	},
	"SHA-256": func(s string) string {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
	},
	"SHA-512-256": func(s string) string {
		return fmt.Sprintf("%x", sha512.Sum512_256([]byte(s)))
	},
}

// TODO: Replace with request.go's (identical) implementation of this if rolled into http package
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

func generateClientNonce() (string, error) {
	// Generates random number
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// TODO: This function totally needs to be split up into constituent parts.
// TODO: Determine whether these args need to be pointers at all? Efficiency is a real contributor to that.
// TODO: Figure out whether a method signature that doesn't rely on http for types is better or more versatile
func getDigestAuth(creds *credential, req *http.Request, resp *http.Response) string {
	// Return quickly in the case that Authorization header can't be constructed
	if resp == nil || resp.Header == nil {
		return ""
	}

	// TODO: Add an option to work with Proxy-Authenticate header (maybe just take in headers overall?)
	// TODO: Make sure Get works correctly for this header name
	// TODO: Make parse (creating params) or accessing params canonicalize param names to all lower-case
	params := parseWwwAuth(resp.Header.Get("Www-Authenticate"))
	// Default to MD5 if algorithm isn't specified in response. TODO: Cite RFC for this
	algoString := valueOrDefault(params["algorithm"], "MD5")
	var sess bool
	// Strip "-sess" from algoString if present
	if strings.HasSuffix(algoString, "-sess") {
		sess = true
		// This assumes that the algorithm value "-sess" will never be specified, and it shouldn't
		algoString = algoString[:len(algoString)-5]
	}
	var algo func(string) string
	if algo = algorithms[algoString]; algo == nil {
		// Full failure if algorithm can't be resolved, since you just can't continue.
		return ""
	}

	realm := params["realm"]
	nonce := params["nonce"]
	cnonce, err := generateClientNonce()
	if err != nil {
		// Refuse to continue if a client nonce can't be generated
		return ""
	}

	// RFC 7616 Section 3.4.2 https://tools.ietf.org/html/rfc7616#section-3.4.2
	var a1 string
	a1Components := []string{unquote(creds.Username), unquote(realm), creds.Password}
	if sess {
		hash := algo(strings.Join(a1Components, ":"))
		a1Components = []string{hash, unquote(nonce), unquote(cnonce)}
		a1 = strings.Join(a1Components, ":")
	} else {
		a1 = strings.Join(a1Components, ":")
	}

	// According to request.go: "For client requests an empty [method] string means GET."
	method := valueOrDefault(req.Method, "GET")
	host := getHost(req)
	// TODO: Use specified requestURI if available.
	// TODO: Figure out whether there are circumstances in which this wouldn't work to get URI
	requestURI := strings.Join(strings.Split(req.URL.String(), host)[1:], host)
	qop := valueOrDefault(params["qop"], "auth")
	qop = strings.Split(qop, ", ")[0]
	// Restores end quote if it was cut off due to truncating a list of values.
	if qop[len(qop)-1:] != `"` {
		qop += `"`
	}
	// RFC 7616 Section 3.4.3 https://tools.ietf.org/html/rfc7616#section-3.4.3
	var a2 string
	a2Components := []string{method, requestURI}
	if qop == "auth-int" {
		// TODO: Determine whether this check is actually necessary.
		if req.Body == nil {
			return ""
		}
		bodyText, err := ioutil.ReadAll(req.Body)
		// TODO: Actually error correctly
		if err != nil {
			fmt.Println(err)
			return ""
		}
		entityBody := string(bodyText)

		a2Components = append(a2Components, algo(entityBody))
		a2 = strings.Join(a2Components, ":")
	} else {
		// Execute if qop is "auth" or unspecified
		a2 = strings.Join(a2Components, ":")
	}

	// TODO: Stop hard-coding nonceCount (nc) as 1. Somehow keep track of that.
	nc := fmt.Sprintf("%08x", 1)

	dataComponents := []string{unquote(nonce), nc, unquote(cnonce), unquote(qop), algo(a2)}
	response := `"` + keyedDigest(algo, algo(a1), strings.Join(dataComponents, ":")) + `"`

	// Username must be hashes after any other hashing, per RFC 7616 Section 3.4.4
	// TODO: Write logic that determines whether to include username or username*, how to encode that
	// TODO: If the username would necessitate using username*, but hashing is enabled, no * is required. Just send the hash.
	username := creds.Username
	userhash := valueOrDefault(params["userhash"], "false")
	if userhash == "true" {
		username = algo(unquote(username) + ":" + unquote(realm))
	}

	return "Digest opaque=" + params["opaque"] + ", algorithm=" + algoString + ", response=" + response + ", username=\"" + username + "\", realm=" + realm + ", uri=\"" + requestURI + "\", qop=" + qop + ", cnonce=\"" + cnonce + "\", nc=" + nc + ", userhash=" + userhash
}

func getBasicAuth(creds *credential) string {
	// Explicitly declare Header so that it's a non-nil map that can be assigned to in .SetBasicAuth
	temp := &http.Request{Header: make(http.Header)}
	temp.SetBasicAuth(creds.Username, creds.Password)
	return temp.Header.Get("Authorization")
}

// TODO: Determine whether these args need to be pointers at all? Efficiency is a real contributor to that.
// TODO: Figure out whether a method signature that doesn't rely on http for types is better or more versatile
// TODO: Really nail down what the correct policy is here.
	// 1) There can be a header or not
	// 2) There can be credentials for a host or not
	// 3) Header can contain scheme that's known, unknown, or none
	// 3) A specified scheme can be "Basic" or "Digest"
// TODO: Invert this so that resp is checked before presence of host
func (auther authenticator) TryGetAuth(req *http.Request, resp *http.Response) string {
	host := getHost(req)
	creds, ok := auther.creds[host]
	// TODO: Maybe act differently if host is empty
	// Credentials were found for the relevant host
	if ok {
		// Response Header exists
		if resp != nil && resp.Header != nil {
			scheme := strings.Split(resp.Header.Get("Www-Authenticate"), " ")[0]
			switch scheme {
			case "Basic":
				return getBasicAuth(creds)
			case "Digest":
				return getDigestAuth(creds, req, resp)
			default:
				return ""
			}
		} else {
			// Guess BasicAuth, avoiding wait for 2nd response if correct
			return getBasicAuth(creds)
		}
	}
	// TODO: Otherwise, assign default creds if those are specified
	return ""
}

// TODO: Handle discrepencies between hostname and ip address
// Should probably be resolved by a DNS lookup? Or maybe mandate all input be IP's.