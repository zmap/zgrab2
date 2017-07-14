package main

import (
	//"encoding/json"
	//"fmt"
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

	//Test output of a marshald options struct, works!
	//if body, err := json.Marshal(zlib.Options[0]); err != nil {
	//	fmt.Println("error: ", err)
	//} else {
	//	os.Stdout.Write(body)
	//}

	zlib.Process(os.Stdout, 2, uint(zlib.NumProtocols))
}
