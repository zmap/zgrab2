package fox

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
)

const (
	// ORIGINAL_QUERY is the hex encoding of the query that will be sent to each server.
	ORIGINAL_QUERY = "666f7820612031202d3120666f782068656c6c6f0a7b0a" +
		"666f782e76657273696f6e3d733a312e300a69643d693a310a686f73744e" +
		"616d653d733a7870766d2d306f6d64633031786d790a686f737441646472" +
		"6573733d733a3139322e3136382e312e3132350a6170702e6e616d653d73" +
		"3a576f726b62656e63680a6170702e76657273696f6e3d733a332e372e34" +
		"340a766d2e6e616d653d733a4a61766120486f7453706f7428544d292053" +
		"657276657220564d0a766d2e76657273696f6e3d733a32302e342d623032" +
		"0a6f732e6e616d653d733a57696e646f77732058500a6f732e7665727369" +
		"6f6e3d733a352e310a6c616e673d733a656e0a74696d655a6f6e653d733a" +
		"416d65726963612f4c6f735f416e67656c65733b2d32383830303030303b" +
		"333630303030303b30323a30303a30302e3030302c77616c6c2c6d617263" +
		"682c382c6f6e206f722061667465722c73756e6461792c756e646566696e" +
		"65643b30323a30303a30302e3030302c77616c6c2c6e6f76656d6265722c" +
		"312c6f6e206f722061667465722c73756e6461792c756e646566696e6564" +
		"0a686f737449643d733a57696e2d393943422d443439442d353434322d30" +
		"3742420a766d557569643d733a38623533306263382d373663352d343133" +
		"392d613265612d3066616264333934643330350a6272616e6449643d733a" +
		"76796b6f6e0a7d3b3b0a"
	// RESPONSE_PREFIX is the prefix that will identify a Fox service.
	RESPONSE_PREFIX = "fox a 0 -1 fox hello"
)

var queryBytes []byte

func init() {
	var err error
	queryBytes, err = hex.DecodeString(ORIGINAL_QUERY)
	if err != nil {
		panic("Could not decode Fox query")
	}
}

// GetFoxBanner sends the static query and reads the response, filling out the logStruct with any fields that are
// present. The IsFox field will identify whether a Fox service was detected, regardless of whether an error was
// returned.
func GetFoxBanner(logStruct *FoxLog, connection net.Conn) error {
	bytesWritten, err := connection.Write(queryBytes)
	if bytesWritten != len(queryBytes) {
		return errors.New("Unable to write all Fox query bytes...")
	}
	if err != nil {
		return err
	}

	data, err := zgrab2.ReadAvailable(connection)
	if err != nil && err != io.EOF {
		return err
	}

	responseString := string(data)
	output := strings.Split(responseString, "\x0a")

	if strings.HasPrefix(responseString, RESPONSE_PREFIX) {
		logStruct.IsFox = true

		for _, value := range output {
			if strings.HasPrefix(value, "fox.version") && strings.Contains(value, ":") {
				logStruct.Version = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "id") && strings.Contains(value, ":") {
				id, err := strconv.ParseUint(strings.Split(value, ":")[1], 10, 32)
				if err != nil {
					return err
				}
				logStruct.Id = uint32(id)
			} else if strings.HasPrefix(value, "hostAddress") && strings.Contains(value, ":") {
				// TODO: What if this is IPv6? Or, more generally, what if any of these contain a colon?
				logStruct.HostAddress = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "hostName") && strings.Contains(value, ":") {
				logStruct.Hostname = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "app.name") && strings.Contains(value, ":") {
				logStruct.AppName = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "app.version") && strings.Contains(value, ":") {
				logStruct.AppVersion = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "vm.name") && strings.Contains(value, ":") {
				logStruct.VMName = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "vm.version") && strings.Contains(value, ":") {
				logStruct.VMVersion = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "os.name") && strings.Contains(value, ":") {
				logStruct.OSName = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "os.version") && strings.Contains(value, ":") {
				logStruct.OSVersion = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "station.name") && strings.Contains(value, ":") {
				logStruct.StationName = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "lang") && strings.Contains(value, ":") {
				logStruct.Language = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "timeZone") && strings.Contains(value, ":") {
				timeZone := strings.Split(value, ":")[1]
				if strings.Contains(timeZone, ";") {
					timeZone = strings.Split(timeZone, ";")[0]
				}
				logStruct.TimeZone = timeZone
			} else if strings.HasPrefix(value, "hostId") && strings.Contains(value, ":") {
				logStruct.HostId = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "vmUuid") && strings.Contains(value, ":") {
				logStruct.VMUuid = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "brandId") && strings.Contains(value, ":") {
				logStruct.BrandId = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "sysInfo") && strings.Contains(value, ":") {
				logStruct.SysInfo = strings.Split(value, ":")[1]
			} else if strings.HasPrefix(value, "authAgentTypeSpecs") && strings.Contains(value, ":") {
				logStruct.AuthAgentType = strings.Split(value, ":")[1]
			}
		}
	}

	return nil
}
