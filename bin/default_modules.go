package bin

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules"
	"github.com/zmap/zgrab2/modules/bacnet"
	"github.com/zmap/zgrab2/modules/banner"
	"github.com/zmap/zgrab2/modules/dnp3"
	"github.com/zmap/zgrab2/modules/fox"
	"github.com/zmap/zgrab2/modules/ftp"
	"github.com/zmap/zgrab2/modules/http"
	"github.com/zmap/zgrab2/modules/imap"
	"github.com/zmap/zgrab2/modules/ipp"
	"github.com/zmap/zgrab2/modules/memcached"
	"github.com/zmap/zgrab2/modules/modbus"
	"github.com/zmap/zgrab2/modules/mongodb"
	"github.com/zmap/zgrab2/modules/mssql"
	"github.com/zmap/zgrab2/modules/mysql"
	"github.com/zmap/zgrab2/modules/ntp"
	"github.com/zmap/zgrab2/modules/oracle"
	"github.com/zmap/zgrab2/modules/pop3"
	"github.com/zmap/zgrab2/modules/postgres"
	"github.com/zmap/zgrab2/modules/redis"
	"github.com/zmap/zgrab2/modules/siemens"
	"github.com/zmap/zgrab2/modules/smb"
	"github.com/zmap/zgrab2/modules/smtp"
	"github.com/zmap/zgrab2/modules/telnet"
)

var defaultModules zgrab2.ModuleSet

func init() {
	defaultModules = map[string]zgrab2.Module{
		"bacnet":    bacnet.NewModule(),
		"banner":    banner.NewModule(),
		"dnp3":      dnp3.NewModule(),
		"fox":       fox.NewModule(),
		"ftp":       ftp.NewModule(),
		"http":      http.NewModule(),
		"imap":      imap.NewModule(),
		"ipp":       ipp.NewModule(),
		"memcached": memcached.NewModule(),
		"modbus":    modbus.NewModule(),
		"mongodb":   mongodb.NewModule(),
		"mssql":     mssql.NewModule(),
		"mysql":     mysql.NewModule(),
		"ntp":       ntp.NewModule(),
		"oracle":    oracle.NewModule(),
		"pop3":      pop3.NewModule(),
		"postgres":  postgres.NewModule(),
		"redis":     redis.NewModule(),
		"siemens":   siemens.NewModule(),
		"smb":       smb.NewModule(),
		"smtp":      smtp.NewModule(),
		"ssh":       &modules.SSHModule{},
		"telnet":    telnet.NewModule(),
		"tls":       &modules.TLSModule{},
	}
}

// NewModuleSetWithDefaults returns a newly allocated ModuleSet containing all
// ScanModules implemented by the ZGrab2 framework.
func NewModuleSetWithDefaults() zgrab2.ModuleSet {
	out := zgrab2.ModuleSet{}
	defaultModules.CopyInto(out)
	return out
}
