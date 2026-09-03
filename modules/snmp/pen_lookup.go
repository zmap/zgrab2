package snmp

var enterpriseNames = map[uint32]string{
	9:     "Cisco Systems",
	11:    "Hewlett Packard",
	42:    "Sun Microsystems",
	43:    "3Com",
	57:    "Ericsson",
	116:   "Agilent Technologies",
	311:   "Microsoft",
	318:   "APC by Schneider Electric",
	674:   "Dell",
	776:   "Telindus Distribution",
	1166:  "Alcatel",
	1588:  "Zebra Technologies",
	1724:  "Alteon WebSystems",
	1916:  "Extreme Networks",
	1991:  "Foundry Networks",
	2011:  "Huawei",
	2021:  "Net-SNMP",
	2272:  "Nortel Networks",
	2636:  "Juniper Networks",
	3076:  "Citrix Systems",
	3224:  "Netscreen Technologies",
	3375:  "F5 Networks",
	4526:  "Netgear",
	5624:  "Enterasys Networks",
	6027:  "Force10 Networks",
	6876:  "VMware",
	7369:  "Meru Networks",
	8072:  "Net-SNMP",
	9303:  "Ericsson AB",
	10002: "Zyxel",
	11898: "Proxim Wireless",
	12356: "Fortinet",
	13742: "Solarwinds",
	14179: "Cisco Aironet",
	14823: "Aruba Networks",
	14988: "MikroTik",
	17163: "Aerohive Networks",
	18334: "Ruckus Wireless",
	20301: "Ubiquiti Networks",
	25461: "Palo Alto Networks",
	25506: "H3C Technologies",
	26543: "Brocade Communications",
	30065: "Arista Networks",
	34278: "Cambium Networks",
	41112: "Ubiquiti Networks",
}

func lookupEnterprise(id uint32) string {
	if name, ok := enterpriseNames[id]; ok {
		return name
	}
	return ""
}
