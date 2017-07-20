package main

import (
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2/zlib"
	"os"
)

var parser = flags.NewParser(&zlib.Options[0], flags.Default)

func main() {
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			log.Fatal("Error: ", err.Error())
		}
	}

	c := zlib.MakeNewController()
	zlib.Process(os.Stdout, c)
}
