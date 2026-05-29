package codesys2

import (
	"bytes"
	"encoding/binary"
)

const CodeSysV2Magic = 0xbbbb
const HeaderSize = 6

type CodeSysV2Header struct {
	Magic  uint16
	Length uint32
}

func (header *CodeSysV2Header) New() {
	header.Magic = CodeSysV2Magic
}

func (header *CodeSysV2Header) SetHeaderSize(payload any) {
	data, err := Marshal(payload, binary.BigEndian)
	if err == nil {
		header.Length = uint32(len(data) - HeaderSize)
	}
}

type CodeSysV2Request struct {
	CodeSysV2Header
	Cmd byte
}

func (request *CodeSysV2Request) New(cmd byte) {
	request.CodeSysV2Header.New()
	request.Cmd = cmd
}

const (
	Login = 0x1

	Logout = 0x2

	Start = 0x3

	Stop = 0x4

	Readvariablelist = 0x5

	Writevariablelist = 0x6

	Enable = 0x7

	Disable = 0x8

	Force = 0x9

	Stepin = 0xa

	Stepover = 0xb

	Setbreakpoint = 0xc

	Deletebreakpoint = 0xd

	Deleteallbreakpoints = 0xe

	Go = 0xf

	Readstatus = 0x10

	Readidentity = 0x11

	Readbreakpointlist = 0x12

	Reset = 0x13

	Definevariablelist = 0x14

	Deletevariablelist = 0x15

	Callstack = 0x17

	Cycle = 0x18

	Defineflowcontrol = 0x19

	Readflowcontrol = 0x1a

	Stopflowcontrol = 0x1b

	Definetrace = 0x1c

	Starttrace = 0x1d

	Readtrace = 0x1e

	Stoptrace = 0x1f

	Forcevariables = 0x20

	Releasevariables = 0x21

	Onlinechange = 0x22

	Startstep = 0x23

	Cyclestep = 0x24

	Defineaccuflow = 0x28

	Definesnapshot = 0x29

	Cancelsnapshot = 0x2a

	Exit = 0x2b

	ReadWritevariable = 0x2c

	Defineconfig = 0x2d

	Readvariablesdirect = 0x2e

	Filewritestart = 0x2f

	Filewritecontinue = 0x30

	Filereadstart = 0x31

	Filereadcontinue = 0x32

	Filereadlist = 0x33

	Filereadinfo = 0x34

	Filerename = 0x35

	Filedelete = 0x36

	Downloadtaskconfig = 0x37

	Definedebugtask = 0x38

	Createbootproject = 0x39

	Downloadsymbols = 0x3a

	Readtaskruntimeinfo = 0x3b

	Writevariablesdirect = 0x3c

	Seteventcycletime = 0x3d

	DownloadIODescription = 0x3e

	Visualizationready = 0x3f

	Downloadprojectinfo = 0x40

	Checkbootproject = 0x41

	Checktargetid = 0x42

	Filetransferdone = 0x43

	Readvariablesex = 0x44

	Writevariablesex = 0x45

	Readvariablesdirectex = 0x46

	Writevariablesdirectex = 0x47

	FileDir = 0x48

	ForceIntracycle = 0x48

	ForceIntracyclePRE = 0x49

	Extendedvariableservice = 0x50

	Extendeddebugservice = 0x51

	GLdownload = 0x64

	GLobserve = 0x65

	GLdownloadblock = 0x66

	Download = 0x80

	Downloadsource = 0x81

	Uploadsource = 0x82

	Flash = 0x83

	Downloadready = 0x8f

	Getlasterror = 0x90

	Setpassword = 0x91

	Browsercommand = 0x92

	ODservice = 0x93
)

type CodeSysV2LoginRequest struct {
	CodeSysV2Request
	Unknown1       uint32
	Unknown2       uint32
	PasswordLength uint32
}

// Login request as anonymous user to get information from the device, even if this is not allowed the device will response with information
func (request *CodeSysV2LoginRequest) New() {
	request.CodeSysV2Request.New(Login)
	request.Unknown1 = 4
	request.Unknown2 = 6
	request.PasswordLength = 0
	request.SetHeaderSize(request)
}

type CodeSysV2LoginResponse struct {
	CodeSysV2Header
	LoginResult uint16
	Unknown1    [56]byte
	OsType      [28]byte
	Unknown2    uint32
	OsVersion   [32]byte
	Vendor      [28]byte
	Unknown3    [56]byte
}

func Marshal(packet any, byteOrder binary.ByteOrder) ([]byte, error) {
	data := make([]byte, 0, 1024)
	buffer := bytes.NewBuffer(data)
	buffer.Reset()
	err := binary.Write(buffer, byteOrder, packet)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), err
}

func UnMarshal(packet []byte, byteOrder binary.ByteOrder, packet_struct any) error {
	buffer := bytes.NewBuffer(packet)
	err := binary.Read(buffer, byteOrder, packet_struct)
	return err
}

type CodeSysV2DeviceInfo struct {
	// The operation system  that runs on the device
	OsType string `json:"os_type"`

	// The operation system version that runs on the device
	OsVersion string `json:"os_version"`

	// The vendor of the device
	Vendor string `json:"vendor"`
}
