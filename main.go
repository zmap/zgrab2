package main

import (
	"github.com/jessevdk/go-flags"
	"log"
	"os"
)

var options [10]Options
var parser = flags.NewParser(&options[0], flags.Default)

func main() {
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			log.Fatal("Error: ", err.Error())
		}
	}
}
