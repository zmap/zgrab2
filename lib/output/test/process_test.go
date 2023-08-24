package test

// FIXME: This is in its own package to work around import loops.

import (
	"encoding/json"
	"fmt"
	"testing"

	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"sync"
	"time"

	"strings"

	"io/ioutil"
	"os/exec"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/encoding/asn1"
	jsonKeys "github.com/zmap/zcrypto/json"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/output"
)

const doFailDiffs = false

// The tests operate by manually constructing the stripped versions of the output.
type Strippable interface {
	Stripped() string
}

// JSON encode the value, then decode it as a map[string]interface{}.
func toMap(v interface{}) map[string]interface{} {
	ret, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		logrus.Fatalf("Error marshaling: %v", err)
	}
	theMap := new(map[string]interface{})
	err = json.Unmarshal(ret, theMap)
	if err != nil {
		logrus.Fatalf("Error unmarshaling: %v", err)
	}
	return *theMap
}

// Get v[key0][key1]...[keyN], or return nil, error if any values along the way
// are nil / not present / not maps.
func mapPath(theMap interface{}, keys ...string) (interface{}, error) {
	for i, key := range keys {
		cast, ok := theMap.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s in map is not a map", strings.Join(keys[0:i], "."))
		}
		theMap = cast
		next, ok := cast[key]
		if !ok {
			return nil, fmt.Errorf("map does not contain %s", strings.Join(keys[0:i+1], "."))
		}
		theMap = next
	}
	return theMap, nil
}

// Set theMap[key0][key1]...[keyN] = value, or return error if any values along
// the way are nil / not present / not maps.
func setMapValue(theMap map[string]interface{}, value interface{}, keys ...string) error {
	lastIndex := len(keys) - 1
	out, err := mapPath(theMap, keys[0:lastIndex]...)
	if err != nil {
		return err
	}
	cast, ok := out.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s in map is not a map", strings.Join(keys[0:lastIndex], "."))
	}
	cast[keys[lastIndex]] = value
	return nil
}

// delete the value at theMap[key0][key1]...[keyN], or return an error if any
// values along the way are nil / not present / not maps.
func delOut(theMap map[string]interface{}, keys ...string) error {
	lastIndex := len(keys) - 1
	out, err := mapPath(theMap, keys[0:lastIndex]...)
	if err != nil {
		return err
	}
	cast, ok := out.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s in map is not a map", strings.Join(keys[0:lastIndex], "."))
	}
	delete(cast, keys[lastIndex])
	return nil
}

// Get a marshalled version of the struct suitable for comparison.
// structs' keys are sorted by order in the definition, which can vary between
// the original and "stripped" versions, the marshalled text is unmarshaled into
// a map (whose keys are sorted alphabetically) and then re-marshaled.
func marshal(v interface{}) string {
	theMap := toMap(v)
	realRet, err := json.MarshalIndent(theMap, "", "  ")
	if err != nil {
		logrus.Fatalf("Error re-marshaling: %v", err)
	}
	return string(realRet)
}

// Get the processed copy of v using the given verbosity value.
func process(verbose bool, v interface{}) interface{} {
	proc := output.NewProcessor()
	proc.Verbose = verbose
	ret, err := proc.Process(v)
	if err != nil {
		panic(err)
	}
	return ret
}

// Return the marshalled  processed copy of v using the given verbosity value.
func strip(verbose bool, v interface{}) string {
	theCopy := process(verbose, v)
	return marshal(theCopy)
}

// Flat value with a wide variety of types, both debug and non-debug.
type Flat struct {
	StringValue    string      `json:"string_value"`
	TrueValue      bool        `json:"true_value"`
	FalseValue     bool        `json:"false_value"`
	IntValue       int         `json:"int_value"`
	BytesValue     []byte      `json:"bytes_value"`
	ArrayValue     [5]string   `json:"array_value"`
	InterfaceValue interface{} `json:"interface_value"`

	PtrStringValue *string    `json:"ptr_string_value"`
	PtrTrueValue   *bool      `json:"ptr_true_value"`
	PtrFalseValue  *bool      `json:"ptr_false_value"`
	PtrIntValue    *int       `json:"ptr_int_value"`
	PtrBytesValue  *[]byte    `json:"ptr_bytes_value"`
	PtrArrayValue  *[5]string `json:"ptr_array_value"`

	DebugStringValue    string      `json:"debug_string_value,omitempty" zgrab:"debug"`
	DebugTrueValue      bool        `json:"debug_true_value,omitempty" zgrab:"debug"`
	DebugFalseValue     bool        `json:"debug_false_value,omitempty" zgrab:"debug"`
	DebugIntValue       int         `json:"debug_int_value,omitempty" zgrab:"debug"`
	DebugBytesValue     []byte      `json:"debug_bytes_value,omitempty" zgrab:"debug"`
	DebugArrayValue     [5]string   `json:"debug_array_value,omitempty" zgrab:"debug"`
	DebugInterfaceValue interface{} `json:"debug_interface_value,omitempty" zgrab:"debug"`

	DebugPtrStringValue *string    `json:"debug_ptr_string_value,omitempty" zgrab:"debug"`
	DebugPtrTrueValue   *bool      `json:"debug_ptr_true_value,omitempty" zgrab:"debug"`
	DebugPtrFalseValue  *bool      `json:"debug_ptr_false_value,omitempty" zgrab:"debug"`
	DebugPtrIntValue    *int       `json:"debug_ptr_int_value,omitempty" zgrab:"debug"`
	DebugPtrBytesValue  *[]byte    `json:"debug_ptr_bytes_value,omitempty" zgrab:"debug"`
	DebugPtrArrayValue  *[5]string `json:"debug_ptr_array_value,omitempty" zgrab:"debug"`
}

type StrippedFlat struct {
	*Flat
	OmitDebugStringValue    string      `json:"debug_string_value,omitempty" zgrab:"debug"`
	OmitDebugTrueValue      bool        `json:"debug_true_value,omitempty" zgrab:"debug"`
	OmitDebugFalseValue     bool        `json:"debug_false_value,omitempty" zgrab:"debug"`
	OmitDebugIntValue       int         `json:"debug_int_value,omitempty" zgrab:"debug"`
	OmitDebugBytesValue     []byte      `json:"debug_bytes_value,omitempty" zgrab:"debug"`
	OmitDebugArrayValue     [5]string   `json:"debug_array_value,omitempty" zgrab:"debug"`
	OmitDebugInterfaceValue interface{} `json:"debug_interface_value,omitempty" zgrab:"debug"`

	OmitDebugPtrStringValue *string    `json:"debug_ptr_string_value,omitempty" zgrab:"debug"`
	OmitDebugPtrTrueValue   *bool      `json:"debug_ptr_true_value,omitempty" zgrab:"debug"`
	OmitDebugPtrFalseValue  *bool      `json:"debug_ptr_false_value,omitempty" zgrab:"debug"`
	OmitDebugPtrIntValue    *int       `json:"debug_ptr_int_value,omitempty" zgrab:"debug"`
	OmitDebugPtrBytesValue  *[]byte    `json:"debug_ptr_bytes_value,omitempty" zgrab:"debug"`
	OmitDebugPtrArrayValue  *[5]string `json:"debug_ptr_array_value,omitempty" zgrab:"debug"`
}

func (flat *Flat) GetStripped() *StrippedFlat {
	return &StrippedFlat{Flat: flat}
}

func (flat *Flat) Stripped() string {
	return marshal(flat.GetStripped())
}

func getStringArray(id string) *[5]string {
	ret := [5]string{}
	for i := 0; i < 5; i++ {
		ret[i] = fmt.Sprintf("%s[%d]", id, i)
	}
	return &ret
}

func pString(s string) *string {
	return &s
}

func pInt(i int) *int {
	return &i
}

func pBool(v bool) *bool {
	return &v
}

func getFlat(id string) *Flat {
	return &Flat{
		StringValue:    id,
		TrueValue:      true,
		FalseValue:     false,
		IntValue:       len(id),
		BytesValue:     []byte{0x64, 0x64, 0x40, 0x05, 0x35, 0x8e},
		ArrayValue:     *getStringArray(id),
		InterfaceValue: &[]byte{0x64, 0x64, 0x40, 0x05, 0x35, 0x8e},

		PtrStringValue: pString(id),
		PtrTrueValue:   pBool(true),
		PtrFalseValue:  pBool(false),
		PtrIntValue:    pInt(len(id)),
		PtrBytesValue:  &[]byte{0x64, 0x64, 0x40, 0x05, 0x35, 0x8e},
		PtrArrayValue:  getStringArray(id),

		DebugStringValue:    "debug_" + id,
		DebugTrueValue:      true,
		DebugFalseValue:     false,
		DebugIntValue:       -len(id),
		DebugBytesValue:     []byte{0x64, 0x64, 0x40, 0x05, 0x35, 0x8e},
		DebugArrayValue:     *getStringArray("debug_" + id),
		DebugInterfaceValue: &[]byte{0x64, 0x64, 0x40, 0x05, 0x35, 0x8e},

		DebugPtrStringValue: pString("debug_" + id),
		DebugPtrTrueValue:   pBool(true),
		DebugPtrFalseValue:  pBool(false),
		DebugPtrIntValue:    pInt(-len(id)),
		DebugPtrBytesValue:  &[]byte{0x64, 0x64, 0x40, 0x05, 0x35, 0x8e},
		DebugPtrArrayValue:  getStringArray("debug_" + id),
	}
}

// An arbitrarily deep struct with debug and non-debug fields
type Deep struct {
	ID      string `json:"id,omitempty"`
	DebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	Child      *Deep `json:"child"`
	DebugChild *Deep `json:"debug_child,omitempty" zgrab:"debug"`

	Flat    Flat  `json:"flat,omitempty"`
	PtrFlat *Flat `json:"ptr_flat,omitempty"`

	DebugFlat    Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	DebugPtrFlat *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

type StrippedDeep struct {
	*Deep

	OmitDebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	OverrideChild  *StrippedDeep `json:"child"`
	OmitDebugChild *StrippedDeep `json:"debug_child,omitempty" zgrab:"debug"`

	OverrideFlat    StrippedFlat  `json:"flat,omitempty"`
	OverridePtrFlat *StrippedFlat `json:"ptr_flat,omitempty"`

	OverrideDebugFlat Flat          `json:"debug_flat" zgrab:"debug"`
	OmitDebugPtrFlat  *StrippedFlat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

func (deep *Deep) GetStripped() *StrippedDeep {
	temp := StrippedDeep{Deep: deep}
	if deep.Child != nil {
		temp.OverrideChild = deep.Child.GetStripped()
	}
	temp.OverrideFlat = *deep.Flat.GetStripped()
	if deep.PtrFlat != nil {
		temp.OverridePtrFlat = deep.PtrFlat.GetStripped()
	}
	temp.OverrideDebugFlat = Flat{}
	// deep.DebugFlat should be "nilled" automatically; if not, tmep.OverrideDebugFlat = StrippedFlat{}
	return &temp
}

func (deep *Deep) Stripped() string {
	return marshal(deep.GetStripped())
}

// getDeep (and all similar functions) takes an identifier string, which is used
// as a prefix for all children, and a depth, which determines how many levels
// of children the return value will have.
func getDeep(id string, depth int) *Deep {
	ret := &Deep{
		ID:           id,
		DebugID:      "debug_" + id,
		Flat:         *getFlat(id + ".flat"),
		PtrFlat:      getFlat(id + ".ptr_flat"),
		DebugFlat:    *getFlat(id + ".debug_flat"),
		DebugPtrFlat: getFlat(id + ".debug_ptr_flat"),
	}
	if depth > 0 {
		ret.Child = getDeep(ret.ID+".child", depth-1)
		ret.DebugChild = getDeep(ret.ID+".debug_child", depth-1)
	}
	return ret
}

// An arbitrarily deep struct, with its children stored as interface{} fields.
type DeepIface struct {
	ID         string      `json:"id"`
	DebugID    string      `json:"debug_id,omitempty" zgrab:"debug"`
	Child      interface{} `json:"child"`
	DebugChild interface{} `json:"debug_child,omitempty" zgrab:"debug"`

	Flat    Flat  `json:"flat,omitempty"`
	PtrFlat *Flat `json:"ptr_flat,omitempty"`

	DebugFlat    Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	DebugPtrFlat *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepIface struct {
	*DeepIface
	OmitDebugID    string      `json:"debug_id,omitempty" zgrab:"debug"`
	OverrideChild  interface{} `json:"child"`
	OmitDebugChild interface{} `json:"debug_child,omitempty" zgrab:"debug"`

	OverrideFlat    StrippedFlat  `json:"flat,omitempty"`
	OverridePtrFlat *StrippedFlat `json:"ptr_flat,omitempty"`

	OverrideDebugFlat Flat          `json:"debug_flat,omitempty" zgrab:"debug"`
	OmitDebugPtrFlat  *StrippedFlat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepIface) GetStripped() *StrippedDeepIface {
	temp := StrippedDeepIface{DeepIface: deep}
	// child and debugChild are both pointers to DeepIface
	if deep.Child != nil {
		temp.OverrideChild = deep.Child.(*DeepIface).GetStripped()
	}
	temp.OverrideFlat = *deep.Flat.GetStripped()
	if deep.PtrFlat != nil {
		temp.OverridePtrFlat = deep.PtrFlat.GetStripped()
	}
	temp.OverrideDebugFlat = Flat{}
	return &temp
}

func (deep *DeepIface) Stripped() string {
	return marshal(deep.GetStripped())
}

func getDeepIface(id string, depth int) *DeepIface {
	ret := &DeepIface{
		ID:           id,
		DebugID:      "debug_" + id,
		Flat:         *getFlat(id + ".flat"),
		PtrFlat:      getFlat(id + ".ptr_flat"),
		DebugFlat:    *getFlat(id + ".debug_flat"),
		DebugPtrFlat: getFlat(id + ".debug_ptr_flat"),
	}
	if depth > 0 {
		ret.Child = getDeepIface(ret.ID+".child", depth-1)
		ret.DebugChild = getDeepIface(ret.ID+".debug_child", depth-1)
	}
	return ret
}

// An arbitrarily deep struct, with its children stored in a slice.
type DeepSlice struct {
	ID      string `json:"id"`
	DebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	Children      []DeepSlice `json:"children"`
	DebugChildren []DeepSlice `json:"debug_children,omitempty" zgrab:"debug"`

	Flat    Flat  `json:"flat,omitempty"`
	PtrFlat *Flat `json:"ptr_flat,omitempty"`

	DebugFlat    Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	DebugPtrFlat *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepSlice struct {
	*DeepSlice
	OmitDebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	OverrideChildren  []StrippedDeepSlice `json:"children"`
	OmitDebugChildren []StrippedDeepSlice `json:"debug_children,omitempty" zgrab:"debug"`

	OverrideFlat    StrippedFlat  `json:"flat,omitempty"`
	OverridePtrFlat *StrippedFlat `json:"ptr_flat,omitempty"`

	OverrideDebugFlat Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	OmitDebugPtrFlat  *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepSlice) GetStripped() *StrippedDeepSlice {
	temp := StrippedDeepSlice{DeepSlice: deep}
	// child and debugChild are both pointers to DeepIface
	if len(deep.Children) > 0 {
		temp.OverrideChildren = make([]StrippedDeepSlice, len(deep.Children))
		for i, v := range deep.Children {
			temp.OverrideChildren[i] = *v.GetStripped()
		}
	}
	temp.OverrideFlat = *deep.Flat.GetStripped()
	if deep.PtrFlat != nil {
		temp.OverridePtrFlat = deep.PtrFlat.GetStripped()
	}
	temp.OverrideDebugFlat = Flat{}
	return &temp
}

func (deep *DeepSlice) Stripped() string {
	return marshal(deep.GetStripped())
}

func getDeepSlice(id string, depth int) *DeepSlice {
	ret := &DeepSlice{
		ID:           id,
		DebugID:      "debug_" + id,
		Flat:         *getFlat(id + ".flat"),
		PtrFlat:      getFlat(id + ".ptr_flat"),
		DebugFlat:    *getFlat(id + ".debug_flat"),
		DebugPtrFlat: getFlat(id + ".debug_ptr_flat"),
	}
	if depth > 0 {
		ret.Children = []DeepSlice{*getDeepSlice(ret.ID+".child", depth-1)}
		ret.DebugChildren = []DeepSlice{*getDeepSlice(ret.ID+".debug_child", depth-1)}
	}
	return ret
}

// An arbitrarily deep struct, with its children stored in an array of pointers.
type DeepArray struct {
	ID      string `json:"id"`
	DebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	Children      [1]*DeepArray `json:"children"`
	DebugChildren [1]*DeepArray `json:"debug_children,omitempty" zgrab:"debug"`

	Flat    Flat  `json:"flat,omitempty"`
	PtrFlat *Flat `json:"ptr_flat,omitempty"`

	DebugFlat    Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	DebugPtrFlat *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepArray struct {
	*DeepArray
	OmitDebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	OverrideChildren  [1]*StrippedDeepArray `json:"children"`
	OmitDebugChildren [1]*StrippedDeepArray `json:"debug_children,omitempty" zgrab:"debug"`

	OverrideFlat    StrippedFlat  `json:"flat,omitempty"`
	OverridePtrFlat *StrippedFlat `json:"ptr_flat,omitempty"`

	OverrideDebugFlat Flat          `json:"debug_flat,omitempty" zgrab:"debug"`
	OmitDebugPtrFlat  *StrippedFlat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepArray) GetStripped() *StrippedDeepArray {
	temp := StrippedDeepArray{DeepArray: deep}
	// child and debugChild are both pointers to DeepIface
	if deep.Children[0] != nil {
		temp.OverrideChildren[0] = deep.Children[0].GetStripped()
	}
	temp.OverrideFlat = *deep.Flat.GetStripped()
	if deep.PtrFlat != nil {
		temp.OverridePtrFlat = deep.PtrFlat.GetStripped()
	}
	temp.OverrideDebugFlat = Flat{}
	return &temp
}

func (deep *DeepArray) Stripped() string {
	return marshal(deep.GetStripped())
}

func getDeepArray(id string, depth int) *DeepArray {
	ret := &DeepArray{
		ID:           id,
		DebugID:      "debug_" + id,
		Flat:         *getFlat(id + ".flat"),
		PtrFlat:      getFlat(id + ".ptr_flat"),
		DebugFlat:    *getFlat(id + ".debug_flat"),
		DebugPtrFlat: getFlat(id + ".debug_ptr_flat"),
	}
	if depth > 0 {
		ret.Children[0] = getDeepArray(ret.ID+".child", depth-1)
		ret.DebugChildren[0] = getDeepArray(ret.ID+".child", depth-1)
	}
	return ret
}

// An arbitrarily deep struct, with its children stored in a slice of interface{}s.
type DeepIfaceSlice struct {
	ID      string `json:"id"`
	DebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	Children      []interface{} `json:"children"`
	DebugChildren []interface{} `json:"debug_children,omitempty" zgrab:"debug"`

	Flat    Flat  `json:"flat,omitempty"`
	PtrFlat *Flat `json:"ptr_flat,omitempty"`

	DebugFlat    Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	DebugPtrFlat *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepIfaceSlice struct {
	*DeepIfaceSlice
	OmitDebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	OverrideChildren  []interface{} `json:"children"`
	OmitDebugChildren []interface{} `json:"debug_children,omitempty" zgrab:"debug"`

	OverrideFlat    StrippedFlat  `json:"flat,omitempty"`
	OverridePtrFlat *StrippedFlat `json:"ptr_flat,omitempty"`

	OverrideDebugFlat Flat          `json:"debug_flat,omitempty" zgrab:"debug"`
	OmitDebugPtrFlat  *StrippedFlat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepIfaceSlice) GetStripped() *StrippedDeepIfaceSlice {
	temp := StrippedDeepIfaceSlice{DeepIfaceSlice: deep}
	// child and debugChild are both pointers to DeepIface
	if len(deep.Children) > 0 {
		child0 := deep.Children[0].(DeepIfaceSlice)
		child1 := deep.Children[1].(Flat)
		temp.OverrideChildren = []interface{}{
			*(&child0).GetStripped(),
			*(&child1).GetStripped(),
		}
	}
	temp.OverrideFlat = *deep.Flat.GetStripped()
	if deep.PtrFlat != nil {
		temp.OverridePtrFlat = deep.PtrFlat.GetStripped()
	}
	temp.OverrideDebugFlat = Flat{}
	return &temp
}

func (deep *DeepIfaceSlice) Stripped() string {
	return marshal(deep.GetStripped())
}

func getDeepIfaceSlice(id string, depth int) *DeepIfaceSlice {
	ret := &DeepIfaceSlice{
		ID:           id,
		DebugID:      "debug_" + id,
		Flat:         *getFlat(id + ".flat"),
		PtrFlat:      getFlat(id + ".ptr_flat"),
		DebugFlat:    *getFlat(id + ".debug_flat"),
		DebugPtrFlat: getFlat(id + ".debug_ptr_flat"),
	}
	if depth > 0 {
		ret.Children = []interface{}{
			*getDeepIfaceSlice(ret.ID+".children[0]", depth-1),
			*getFlat(id + ".children[1]"),
		}
		ret.DebugChildren = []interface{}{
			*getDeepIfaceSlice(ret.ID+".debug_children[0]", depth-1),
			*getFlat(ret.ID + ".debug_children[1]"),
		}
	}
	return ret
}

// An arbitrarily deep struct, with its children stored in an array of interface{}s
type DeepIfaceArray struct {
	ID      string `json:"id"`
	DebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	Children      [2]interface{} `json:"children"`
	DebugChildren [2]interface{} `json:"debug_children,omitempty" zgrab:"debug"`

	Flat    Flat  `json:"flat,omitempty"`
	PtrFlat *Flat `json:"ptr_flat,omitempty"`

	DebugFlat    Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	DebugPtrFlat *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepIfaceArray struct {
	*DeepIfaceArray
	OmitDebugID string `json:"debug_id,omitempty" zgrab:"debug"`

	OverrideChildren  [2]interface{} `json:"children"`
	OmitDebugChildren [2]interface{} `json:"debug_children,omitempty" zgrab:"debug"`

	OverrideFlat    StrippedFlat  `json:"flat,omitempty"`
	OverridePtrFlat *StrippedFlat `json:"ptr_flat,omitempty"`

	OverrideDebugFlat Flat          `json:"debug_flat,omitempty" zgrab:"debug"`
	OmitDebugPtrFlat  *StrippedFlat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepIfaceArray) GetStripped() *StrippedDeepIfaceArray {
	temp := StrippedDeepIfaceArray{DeepIfaceArray: deep}
	// child and debugChild are both pointers to DeepIface
	if deep.Children[0] != nil {
		temp.OverrideChildren[0] = deep.Children[0].(*DeepIfaceArray).GetStripped()
	}
	if deep.Children[1] != nil {
		temp.OverrideChildren[1] = deep.Children[1].(*Flat).GetStripped()
	}
	temp.OverrideFlat = *deep.Flat.GetStripped()
	if deep.PtrFlat != nil {
		temp.OverridePtrFlat = deep.PtrFlat.GetStripped()
	}
	temp.OverrideDebugFlat = Flat{}
	return &temp
}

func (deep *DeepIfaceArray) Stripped() string {
	return marshal(deep.GetStripped())
}

func getDeepIfaceArray(id string, depth int) *DeepIfaceArray {
	ret := &DeepIfaceArray{
		ID:           id,
		DebugID:      "debug_" + id,
		Flat:         *getFlat(id + ".flat"),
		PtrFlat:      getFlat(id + ".ptr_flat"),
		DebugFlat:    *getFlat(id + ".debug_flat"),
		DebugPtrFlat: getFlat(id + ".debug_ptr_flat"),
	}
	if depth > 0 {
		ret.Children[0] = getDeepIfaceArray(ret.ID+".children[0]", depth-1)
		ret.Children[1] = getFlat(ret.ID + ".children[1]")
		ret.DebugChildren[0] = getDeepIfaceArray(ret.ID+".debug_children[0]", depth-1)
		ret.DebugChildren[1] = getFlat(ret.ID + ".debug_children[1]")
	}
	return ret
}

// A wrapper around a Deep, with field names prefixed with anon0 so that it can
// be used as an anonymous member struct.
type DeepAnon0 struct {
	Anon0ID      string `json:"anon0_id,omitempty"`
	DebugAnon0ID string `json:"debug_anon0_id,omitempty" zgrab:"debug"`

	Anon0      Deep `json:"anon0,omitempty"`
	DebugAnon0 Deep `json:"debug_anon0,omitempty" zgrab:"debug"`

	Anon0Flat    Flat  `json:"anon0_flat,omitempty"`
	PtrAnon0Flat *Flat `json:"ptr_anon0_flat,omitempty"`

	DebugAnon0Flat    Flat  `json:"debug_anon0_flat,omitempty" zgrab:"debug"`
	DebugPtrAnon0Flat *Flat `json:"debug_ptr_anon0_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepAnon0 struct {
	*DeepAnon0
	OmitDebugAnon0ID string `json:"debug_anon0_id,omitempty" zgrab:"debug"`

	OverrideAnon0      StrippedDeep `json:"anon0,omitempty"`
	OverrideDebugAnon0 Deep         `json:"debug_anon0,omitempty" zgrab:"debug"`

	OverrideAnon0Flat    StrippedFlat  `json:"anon0_flat,omitempty"`
	OverridePtrAnon0Flat *StrippedFlat `json:"ptr_anon0_flat,omitempty"`

	OverrideDebugAnon0Flat Flat  `json:"debug_anon0_flat" zgrab:"debug"`
	OmitDebugPtrAnon0Flat  *Flat `json:"debug_ptr_anon0_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepAnon0) GetStripped() *StrippedDeepAnon0 {
	temp := StrippedDeepAnon0{DeepAnon0: deep}
	// child and debugChild are both pointers to DeepIface
	temp.OverrideAnon0 = *deep.Anon0.GetStripped()
	temp.OverrideDebugAnon0 = Deep{}
	temp.OverrideAnon0Flat = *deep.Anon0Flat.GetStripped()
	temp.OverridePtrAnon0Flat = deep.PtrAnon0Flat.GetStripped()

	temp.OverrideDebugAnon0Flat = Flat{}
	return &temp
}

func (deep *DeepAnon0) Stripped() string {
	return marshal(deep.GetStripped())
}

// A wrapper around a Deep, with field names prefixed with anon1 so that it can
// be used as an anonymous member struct.
type DeepAnon1 struct {
	Anon1ID      string `json:"anon1_id"`
	DebugAnon1ID string `json:"debug_anon1_id,omitempty" zgrab:"debug"`

	Anon1      Deep `json:"anon1"`
	DebugAnon1 Deep `json:"debug_anon1,omitempty" zgrab:"debug"`

	Anon1Flat    Flat  `json:"anon1_flat,omitempty"`
	PtrAnon1Flat *Flat `json:"ptr_anon1_flat,omitempty"`

	DebugAnon1Flat    Flat  `json:"debug_anon1_flat,omitempty" zgrab:"debug"`
	DebugPtrAnon1Flat *Flat `json:"debug_ptr_anon1_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepAnon1 struct {
	*DeepAnon1
	OmitDebugAnon1ID string `json:"debug_anon1_id,omitempty" zgrab:"debug"`

	OverrideAnon1      StrippedDeep `json:"anon1,omitempty"`
	OverrideDebugAnon1 Deep         `json:"debug_anon1,omitempty" zgrab:"debug"`

	OverrideAnon1Flat    StrippedFlat  `json:"anon1_flat,omitempty"`
	OverridePtrAnon1Flat *StrippedFlat `json:"ptr_anon1_flat,omitempty"`

	OverrideDebugAnon1Flat Flat  `json:"debug_anon1_flat" zgrab:"debug"`
	OmitDebugPtrAnon1Flat  *Flat `json:"debug_ptr_anon1_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepAnon1) GetStripped() *StrippedDeepAnon1 {
	temp := StrippedDeepAnon1{DeepAnon1: deep}
	// child and debugChild are both pointers to DeepIface
	temp.OverrideAnon1 = *deep.Anon1.GetStripped()
	temp.OverrideDebugAnon1 = Deep{}
	temp.OverrideAnon1Flat = *deep.Anon1Flat.GetStripped()
	temp.OverridePtrAnon1Flat = deep.PtrAnon1Flat.GetStripped()

	temp.OverrideDebugAnon1Flat = Flat{}
	return &temp
}

func (deep *DeepAnon1) Stripped() string {
	return marshal(deep.GetStripped())
}

// An arbitrarily deep struct, with a pair of anonymous member structs (one a pointer).
type DeepAnon struct {
	DeepAnon0
	*DeepAnon1

	ID         string    `json:"id"`
	DebugID    string    `json:"debug_id,omitempty" zgrab:"debug"`
	Child      *DeepAnon `json:"child,omitempty"`
	DebugChild *DeepAnon `json:"debug_child,omitempty" zgrab:"debug"`

	Flat    Flat  `json:"flat,omitempty"`
	PtrFlat *Flat `json:"ptr_flat,omitempty"`

	DebugFlat    Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	DebugPtrFlat *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

type StrippedDeepAnon struct {
	*DeepAnon
	*StrippedDeepAnon0
	*StrippedDeepAnon1

	OverrideAnon0ID string `json:"anon0_id,omitempty"`
	OverrideAnon1ID string `json:"anon1_id,omitempty"`

	OmitDebugID    string            `json:"debug_id,omitempty" zgrab:"debug"`
	OverrideChild  *StrippedDeepAnon `json:"child,omitempty"`
	OmitDebugChild *StrippedDeepAnon `json:"debug_child,omitempty" zgrab:"debug"`

	OverrideFlat    StrippedFlat  `json:"flat,omitempty"`
	OverridePtrFlat *StrippedFlat `json:"ptr_flat,omitempty"`

	OverrideDebugFlat Flat  `json:"debug_flat,omitempty" zgrab:"debug"`
	OmitDebugPtrFlat  *Flat `json:"debug_ptr_flat,omitempty" zgrab:"debug"`
}

func (deep *DeepAnon) GetStripped() *StrippedDeepAnon {
	temp := StrippedDeepAnon{
		DeepAnon:          deep,
		StrippedDeepAnon0: deep.DeepAnon0.GetStripped(),
		StrippedDeepAnon1: deep.DeepAnon1.GetStripped(),
		OverrideAnon0ID:   deep.DeepAnon0.Anon0ID,
		OverrideAnon1ID:   deep.DeepAnon1.Anon1ID,
	}
	if deep.Child != nil {
		temp.OverrideChild = deep.Child.GetStripped()
	}
	temp.OverrideFlat = *deep.Flat.GetStripped()
	if deep.PtrFlat != nil {
		temp.OverridePtrFlat = deep.PtrFlat.GetStripped()
	}
	temp.OverrideDebugFlat = Flat{}

	return &temp
}

func (deep *DeepAnon) Stripped() string {
	return marshal(deep.GetStripped())
}

func getDeepAnon(id string, depth int) *DeepAnon {
	ret := &DeepAnon{
		DeepAnon0: DeepAnon0{
			Anon0ID:           id + ".anon0",
			DebugAnon0ID:      id + ".debug_anon0",
			Anon0:             *getDeep(id+".anon0", depth-1),
			DebugAnon0:        *getDeep(id+".anon0", depth-1),
			Anon0Flat:         *getFlat(id + ".anon0_flat"),
			PtrAnon0Flat:      getFlat(id + ".ptr_anon0_flat"),
			DebugAnon0Flat:    *getFlat(id + ".debug_anon0_flat"),
			DebugPtrAnon0Flat: getFlat(id + ".debug_ptr_anon0_flat"),
		},
		DeepAnon1: &DeepAnon1{
			Anon1ID:           id + ".anon1",
			DebugAnon1ID:      id + ".debug_anon1",
			Anon1:             *getDeep(id+".anon1", depth-1),
			DebugAnon1:        *getDeep(id+".anon1", depth-1),
			Anon1Flat:         *getFlat(id + ".anon1_flat"),
			PtrAnon1Flat:      getFlat(id + ".ptr_anon1_flat"),
			DebugAnon1Flat:    *getFlat(id + ".debug_anon1_flat"),
			DebugPtrAnon1Flat: getFlat(id + ".debug_ptr_anon1_flat"),
		},
		ID:        id,
		DebugID:   "debug_" + id,
		Flat:      *getFlat(id + ".flat"),
		DebugFlat: *getFlat(id + ".debug_flat"),
	}
	if depth > 0 {
		ret.Child = getDeepAnon(id+".child", depth-1)
		ret.DebugChild = getDeepAnon(id+".debug_child", depth-1)
	}
	return ret
}

func fail(t *testing.T, id string, expected string, actual string) {
	t.Logf("%s: mismatch: expected %s, got %s", id, expected, actual)
	if doFailDiffs {
		ioutil.WriteFile(id+"-expected.json", []byte(expected), 0)
		ioutil.WriteFile(id+"-actual.json", []byte(actual), 0)
		cmd := exec.Command("diff", "-u", id+"-expected.json", id+"-actual.json")
		ret, _ := cmd.Output()
		ioutil.WriteFile(id+".diff", ret, 0)
	}
	t.Errorf("%s mismatch", id)
}

// Test processing all of the different types, in verbose and default mode, in parallel.
func TestProcess(t *testing.T) {
	tests := map[string]Strippable{
		"flat":           getFlat("flat"),
		"deep":           getDeep("deep", 3),
		"deepAnon":       getDeepAnon("deepAnon", 3),
		"deepArray":      getDeepArray("deepArray", 3),
		"deepIface":      getDeepIface("deepIface", 3),
		"deepIfaceArray": getDeepIfaceArray("deepIfaceArray", 3),
		"deepIfaceSlice": getDeepIfaceSlice("deepIfaceSlice", 3),
		"deepSlice":      getDeepSlice("deepSlice", 3),
	}

	doTest := func(verbose bool, id string, input Strippable) {
		var testID string
		if verbose {
			testID = id + "-verbose"
		} else {
			testID = id + "-default"
		}
		var expected string
		if verbose {
			expected = marshal(input)
		} else {
			expected = input.Stripped()
		}
		actual := strip(verbose, input)
		if expected != actual {
			fail(t, testID, expected, actual)
		}
	}
	doTests := func(verbose bool) {
		var done sync.WaitGroup
		done.Add(len(tests))
		for k, v := range tests {
			//done.Add(1)
			go func(id string, input Strippable) {
				defer done.Done()
				doTest(verbose, id, input)
			}(k, v)
			//done.Wait()
		}
		done.Wait()
	}
	doTests(true)
	doTests(false)
}

func _b64(s string) []byte {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

func _hex(s string) []byte {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

type fakeMySQLScanResults struct {
	// ProtocolVersion is the 8-bit unsigned integer representing the
	// server's protocol version sent in the initial HandshakePacket from
	// the server.
	// This has been 10 for all MySQL versionssince 3.2.2 (from 1998).
	ProtocolVersion byte `json:"protocol_version"`

	// ServerVersion is a null-terminated string giving the specific
	// server version in the initial HandshakePacket. Often of the format
	// x.y.z, but not always.
	ServerVersion string `json:"server_version"`

	// ConnectionID is the server's internal identifier for this client's
	// connection, sent in the initial HandshakePacket.
	ConnectionID uint32 `json:"connection_id" zgrab:"debug"`

	// AuthPluginData is optional plugin-specific data, whose meaning
	// depends on the value of AuthPluginName. Returned in the initial
	// HandshakePacket.
	AuthPluginData []byte `json:"auth_plugin_data" zgrab:"debug"`

	// CharacterSet is the identifier for the character set the server is
	// using. Returned in the initial HandshakePacket.
	CharacterSet byte `json:"character_set,omitempty" zgrab:"debug"`

	// StatusFlags is the set of status flags the server returned in the
	// initial HandshakePacket. Each true entry in the map corresponds to
	// a bit set to 1 in the flags, where the keys correspond to the
	// #defines in the MySQL docs.
	StatusFlags map[string]bool `json:"status_flags"`

	// CapabilityFlags is the set of capability flags the server returned
	// initial HandshakePacket. Each true entry in the map corresponds to
	// a bit set to 1 in the flags, where the keys correspond to the
	// #defines in the MySQL docs.
	CapabilityFlags map[string]bool `json:"capability_flags"`

	// AuthPluginName is the name of the authentication plugin, returned
	// in the initial HandshakePacket.
	AuthPluginName string `json:"auth_plugin_name,omitempty" zgrab:"debug"`

	// ErrorCode is only set if there is an error returned by the server,
	// for example if the scanner is not on the allowed hosts list.
	ErrorCode *int `json:"error_code,omitempty"`

	// ErrorMessage is an optional string describing the error. Only set
	// if there is an error.
	ErrorMessage string `json:"error_message,omitempty"`

	// RawPackets contains the base64 encoding of all packets sent and
	// received during the scan.
	RawPackets []string `json:"raw_packets,omitempty"`

	// TLSLog contains the usual shared TLS logs.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// TestMySQL builds a bogus MySQL result, and then manually checks that the
// debug fields (and only the debug fields) are omitted.
func TestMySQL(t *testing.T) {
	results := fakeMySQLScanResults{}
	results.AuthPluginData = []byte("auth plugin data")
	results.CapabilityFlags = map[string]bool{
		"CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS":    true,
		"CLIENT_COMPRESS":                        true,
		"CLIENT_SSL":                             true,
		"CLIENT_SECURE_CONNECTION":               true,
		"CLIENT_INTERACTIVE":                     true,
		"CLIENT_PLUGIN_AUTH":                     true,
		"CLIENT_PLUGIN_AUTH_LEN_ENC_CLIENT_DATA": true,
		"CLIENT_PROTOCOL_41":                     true,
	}
	results.ProtocolVersion = 10
	results.RawPackets = []string{
		"dGhpcyBpcyBub3QgYSByZWFsIHBhY2tldA==",
		"bm9yIGlzIHRoaXM=",
	}
	results.ConnectionID = 1234
	results.ServerVersion = "8.0.3-rc-log"
	results.StatusFlags = map[string]bool{
		"SERVER_STATUS_AUTOCOMMIT": true,
	}
	results.TLSLog = new(zgrab2.TLSLog)
	results.TLSLog.HandshakeLog = &tls.ServerHandshake{
		ClientFinished: &tls.Finished{
			VerifyData: []byte("not real data"),
		},
		ClientHello: &tls.ClientHello{
			CipherSuites: []tls.CipherSuite{
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods:  []tls.CompressionMethod{0x00},
			OcspStapling:        true,
			Random:              []byte("some random data"),
			SecureRenegotiation: true,
			// leaving out SignatureAndHashes, since these aren't exported (yet?)
			SupportedCurves: []tls.CurveID{
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
			},
			SupportedPoints: []tls.PointFormat{0},
			Version:         0x303,
		},
		ClientKeyExchange: &tls.ClientKeyExchange{
			RSAParams: &jsonKeys.RSAClientParams{
				EncryptedPMS: []byte("fake"),
				Length:       4,
			},
		},
		KeyMaterial: &tls.KeyMaterial{
			MasterSecret: &tls.MasterSecret{
				Value:  []byte("fake"),
				Length: 4,
			},
			PreMasterSecret: &tls.PreMasterSecret{
				Value:  []byte("fake"),
				Length: 4,
			},
		},
		ServerCertificates: &tls.Certificates{
			Certificate: tls.SimpleCertificate{
				Raw: _b64("MIIC9DCCAdwCAQIwDQYJKoZIhvcNAQELBQAwPjE8MDoGA1UEAwwzTXlTUUxfU2VydmVyXzguMC4zLXJjX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4XDTE4MDMyMzE5MDMyOFoXDTI4MDMyMDE5MDMyOFowQjFAMD4GA1UEAww3TXlTUUxfU2VydmVyXzguMC4zLXJjX0F1dG9fR2VuZXJhdGVkX1NlcnZlcl9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALspPX60RdH8fgSsBjvXRhJ3egQBQWRoga8iGqAjdYrapvNwsdNqzsIe1v+q0FzIKwTkrrGQ3At1ikBjxOhobJOeNeB84jJp+72lPQM2ngYUx3ua/zwZKQw+vZIIqeGPnLzAc180anZl9AL5olyMR+sWm23+YCqEWK0+o9UW5tj27HOX5dL/xZSX+Y8Hsp/1cMK0AmReUsejNobfJ9jBomfKJRiyrEm4Zp3nCA8SuHByboQcKONHMWHeuvvSH5k/ndNf53yw7B/fYua8DHfZ9JUOIZfiGTPJFy1a7zLpIE0fjKRIVaGgggZA9lJzlnNVKna5KT92q+Vi4qgg5pPVqVUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAiOYzSZapOpbSqJHAwpjQRhF02xu8f2sqeckpvROzDMRaq7lP/b5No51Sc7mqe2FrDB2O80G8qwZiM06INRd4HaoKDvolXD+xpyBZ5daNY09/ucpg8f1gDr83sS++AT+LHeoQ9ZmbpRn/x2ZfwA3L8fAoOJg/9m1Z07JOX/9h2uKgZVZBvIQNdm7QSjM7hqgHAcBQVVgk6p2BVd17RYuM9SXJIaCrCKJlg2EcBDyqSD4bdXm941o3+if7eeaTXkBlPzj7MzmrQnaI1Q11LfUrrrNrYDqv1DgIAwMIQ3BzqsJ4GQipq1z5DqU3I8jz0LtsI6J8hFqQf5zQDTuxP3b+tw=="),
				Parsed: &x509.Certificate{
					Raw:                     _b64("MIIC9DCCAdwCAQIwDQYJKoZIhvcNAQELBQAwPjE8MDoGA1UEAwwzTXlTUUxfU2VydmVyXzguMC4zLXJjX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4XDTE4MDMyMzE5MDMyOFoXDTI4MDMyMDE5MDMyOFowQjFAMD4GA1UEAww3TXlTUUxfU2VydmVyXzguMC4zLXJjX0F1dG9fR2VuZXJhdGVkX1NlcnZlcl9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALspPX60RdH8fgSsBjvXRhJ3egQBQWRoga8iGqAjdYrapvNwsdNqzsIe1v+q0FzIKwTkrrGQ3At1ikBjxOhobJOeNeB84jJp+72lPQM2ngYUx3ua/zwZKQw+vZIIqeGPnLzAc180anZl9AL5olyMR+sWm23+YCqEWK0+o9UW5tj27HOX5dL/xZSX+Y8Hsp/1cMK0AmReUsejNobfJ9jBomfKJRiyrEm4Zp3nCA8SuHByboQcKONHMWHeuvvSH5k/ndNf53yw7B/fYua8DHfZ9JUOIZfiGTPJFy1a7zLpIE0fjKRIVaGgggZA9lJzlnNVKna5KT92q+Vi4qgg5pPVqVUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAiOYzSZapOpbSqJHAwpjQRhF02xu8f2sqeckpvROzDMRaq7lP/b5No51Sc7mqe2FrDB2O80G8qwZiM06INRd4HaoKDvolXD+xpyBZ5daNY09/ucpg8f1gDr83sS++AT+LHeoQ9ZmbpRn/x2ZfwA3L8fAoOJg/9m1Z07JOX/9h2uKgZVZBvIQNdm7QSjM7hqgHAcBQVVgk6p2BVd17RYuM9SXJIaCrCKJlg2EcBDyqSD4bdXm941o3+if7eeaTXkBlPzj7MzmrQnaI1Q11LfUrrrNrYDqv1DgIAwMIQ3BzqsJ4GQipq1z5DqU3I8jz0LtsI6J8hFqQf5zQDTuxP3b+tw=="),
					RawTBSCertificate:       _b64("MIIB3AIBAjANBgkqhkiG9w0BAQsFADA+MTwwOgYDVQQDDDNNeVNRTF9TZXJ2ZXJfOC4wLjMtcmNfQXV0b19HZW5lcmF0ZWRfQ0FfQ2VydGlmaWNhdGUwHhcNMTgwMzIzMTkwMzI4WhcNMjgwMzIwMTkwMzI4WjBCMUAwPgYDVQQDDDdNeVNRTF9TZXJ2ZXJfOC4wLjMtcmNfQXV0b19HZW5lcmF0ZWRfU2VydmVyX0NlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyk9frRF0fx+BKwGO9dGEnd6BAFBZGiBryIaoCN1itqm83Cx02rOwh7W/6rQXMgrBOSusZDcC3WKQGPE6Ghsk5414HziMmn7vaU9AzaeBhTHe5r/PBkpDD69kgip4Y+cvMBzXzRqdmX0AvmiXIxH6xabbf5gKoRYrT6j1Rbm2Pbsc5fl0v/FlJf5jweyn/VwwrQCZF5Sx6M2ht8n2MGiZ8olGLKsSbhmnecIDxK4cHJuhBwo40cxYd66+9IfmT+d01/nfLDsH99i5rwMd9n0lQ4hl+IZM8kXLVrvMukgTR+MpEhVoaCCBkD2UnOWc1UqdrkpP3ar5WLiqCDmk9WpVQIDAQAB"),
					RawSubjectPublicKeyInfo: _b64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyk9frRF0fx+BKwGO9dGEnd6BAFBZGiBryIaoCN1itqm83Cx02rOwh7W/6rQXMgrBOSusZDcC3WKQGPE6Ghsk5414HziMmn7vaU9AzaeBhTHe5r/PBkpDD69kgip4Y+cvMBzXzRqdmX0AvmiXIxH6xabbf5gKoRYrT6j1Rbm2Pbsc5fl0v/FlJf5jweyn/VwwrQCZF5Sx6M2ht8n2MGiZ8olGLKsSbhmnecIDxK4cHJuhBwo40cxYd66+9IfmT+d01/nfLDsH99i5rwMd9n0lQ4hl+IZM8kXLVrvMukgTR+MpEhVoaCCBkD2UnOWc1UqdrkpP3ar5WLiqCDmk9WpVQIDAQAB"),
					RawSubject:              _b64("MEIxQDA+BgNVBAMMN015U1FMX1NlcnZlcl84LjAuMy1yY19BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGU="),
					RawIssuer:               _b64("MD4xPDA6BgNVBAMMM015U1FMX1NlcnZlcl84LjAuMy1yY19BdXRvX0dlbmVyYXRlZF9DQV9DZXJ0aWZpY2F0ZQ=="),
					Signature:               _b64("iOYzSZapOpbSqJHAwpjQRhF02xu8f2sqeckpvROzDMRaq7lP/b5No51Sc7mqe2FrDB2O80G8qwZiM06INRd4HaoKDvolXD+xpyBZ5daNY09/ucpg8f1gDr83sS++AT+LHeoQ9ZmbpRn/x2ZfwA3L8fAoOJg/9m1Z07JOX/9h2uKgZVZBvIQNdm7QSjM7hqgHAcBQVVgk6p2BVd17RYuM9SXJIaCrCKJlg2EcBDyqSD4bdXm941o3+if7eeaTXkBlPzj7MzmrQnaI1Q11LfUrrrNrYDqv1DgIAwMIQ3BzqsJ4GQipq1z5DqU3I8jz0LtsI6J8hFqQf5zQDTuxP3b+tw=="),
					SignatureAlgorithm:      4,
					SignatureAlgorithmOID:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
					PublicKeyAlgorithm:      x509.PublicKeyAlgorithm(1),
					PublicKey: &rsa.PublicKey{
						N: (&big.Int{}).SetBytes(_hex("23626899336418032268426511006251456008957710946561236060077488477243930404389062857052756514213142729464147136250009726616710651748049570319952455766122793111751860932493085339042549427591735641622561350827399950711160330519889423606741185340361830307539991923398265174995648216248341512414059342081655136496339884654761519474219238937533274055680590823298754387287727134545334674412201273293183886639463834612608672984702302550038373374767049834134869307465746789634588312053503628028754854224411402349197656713279667931626157560702246437041136455602220365024967237813532823227555845248339489268414093584421359036757")),
						E: 65537,
					},
					PublicKeyAlgorithmOID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
					Version:               2,
					SerialNumber:          big.NewInt(2),
					Issuer: pkix.Name{
						CommonName: "MySQL_Server_8.0.3-rc_Auto_Generated_CA_Certificate",
						Names: []pkix.AttributeTypeAndValue{pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3},
							Value: "MySQL_Server_8.0.3-rc_Auto_Generated_CA_Certificate"}},
						ExtraNames: []pkix.AttributeTypeAndValue(nil),
						OriginalRDNS: pkix.RDNSequence{pkix.RelativeDistinguishedNameSET{pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3},
							Value: "MySQL_Server_8.0.3-rc_Auto_Generated_CA_Certificate"}}}},
					Subject: pkix.Name{
						CommonName: "MySQL_Server_8.0.3-rc_Auto_Generated_Server_Certificate",
						Names: []pkix.AttributeTypeAndValue{pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3},
							Value: "MySQL_Server_8.0.3-rc_Auto_Generated_Server_Certificate"}},
						ExtraNames: []pkix.AttributeTypeAndValue(nil),
						OriginalRDNS: pkix.RDNSequence{pkix.RelativeDistinguishedNameSET{pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3},
							Value: "MySQL_Server_8.0.3-rc_Auto_Generated_Server_Certificate"}}}},
					NotBefore:                 time.Unix(63657428608/1000, 0),
					NotAfter:                  time.Unix(63972788608/1000, 0),
					ValidityPeriod:            315360000,
					KeyUsage:                  0,
					SPKISubjectFingerprint:    x509.CertificateFingerprint(_hex("14ffb1395597876cf13957c7de6994f7361efa951ceb49e222897ec964566c98")),
					SPKIFingerprint:           x509.CertificateFingerprint(_hex("66bedbc8b8f7df04f2dea4eb7d351f4f7f2b88b51eb52b988f8579201f9e5f3c")),
					TBSCertificateFingerprint: x509.CertificateFingerprint(_hex("2cfc9ad82b7871734febcc892f61c81c4d8cf051ac071d357c8b9d08a13a2707")),
					FingerprintNoCT:           x509.CertificateFingerprint(_hex("a678d89928d1b7d398c1bc194bf393aac70239876b3f17da15c0fe5d1cde34f7")),
					FingerprintSHA256:         x509.CertificateFingerprint(_hex("202dc36b950a33f12237dd6197a60c06ddaba945b8c281d811c7b1a6d45b0640")),
					FingerprintSHA1:           x509.CertificateFingerprint(_hex("48e5d105675ea12ef95f7ef31eb8af3639ee57b2")),
					FingerprintMD5:            x509.CertificateFingerprint(_hex("da94c3e3592de3da093c5da51f46d4ce")),
				},
			},
		},
		ServerFinished: &tls.Finished{
			VerifyData: []byte("fake"),
		},
		ServerHello: &tls.ServerHello{
			CipherSuite:       tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			CompressionMethod: 0,
			Random:            []byte("some other random data"),
			SessionID:         []byte("some session ID"),
			Version:           0x302,
		},
	}
	results.TLSLog.HeartbleedLog = &tls.Heartbleed{}
	mapVal := toMap(results)
	mapVal["auth_plugin_data"] = nil
	mapVal["connection_id"] = 0
	delOut(mapVal, "tls", "handshake_log", "client_hello")
	expected := marshal(mapVal)
	actual := strip(false, results)
	if actual != expected {
		fail(t, "fake-mysql", expected, actual)
	}
}
