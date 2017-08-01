package zgrab2

import (
	"github.com/jessevdk/go-flags"
)

var Parser *flags.Parser

func init() {
	Parser = flags.NewParser(&options, flags.Default)
}
