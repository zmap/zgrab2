package modules

import (
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/http"
)

func init() {
	m := http.NewModule()
	cmd, err := zgrab2.AddCommand(m.Protocol(), m.ShortDescription(), m.Description(), m.DefaultPort(), m)
	if err != nil {
		log.Fatal(err)
	}
	// The above AddCommand will set the default port to 0, but we'll set it dynamically in Init(), removing the default
	cmd.FindOptionByLongName("port").Default = nil
	// Add custom port description for http vs. https
	cmd.FindOptionByLongName("port").Description = "Specify port to grab on (default: 80 for HTTP, 443 when used with --use-https)"
}
