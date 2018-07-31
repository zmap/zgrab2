package httpauth

import (
	"bufio"
	"io/ioutil"
	"os"
)

var Credentials map[string]Credential

// Cred type to generate
type Credential struct {
	username, password string
}

// Some function which will prepare this process by taking in all the requisite
// information from the cred file to get set up
// TODO: Determine return type
func Prepare(path string) {
	

}

// Discrepencies between hostname and ip address
// Should probably be resolved by a DNS lookup? Or maybe mandate all input be IP's.