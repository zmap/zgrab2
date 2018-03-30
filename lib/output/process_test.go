package output

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"sync"
	"io/ioutil"
	"os/exec"
	"bytes"
)

// The tests operate by manually constructing the stripped versions of the output.
type Strippable interface {
	Stripped() string
}

// Get a marshalled version of the struct suitable for comparison.
// structs' keys are sorted by order in the definition, which can vary between
// the original and "stripped" versions, the marshalled text is unmarshaled into
// a map (whose keys are sorted alphabetically) and then re-marshaled.
func marshal(v interface{}) string {
	ret, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		logrus.Fatalf("Error marshaling: %v", err)
	}
	theMap := new(map[string]interface{})
	err = json.Unmarshal(ret, theMap)
	if err != nil {
		logrus.Fatalf("Error unmarshaling: %v", err)
	}
	realRet, err := json.MarshalIndent(theMap, "", "  ")
	if err != nil {
		logrus.Fatalf("Error re-marshaling: %v", err)
	}
	return string(realRet)
}

// Helper to process then marshal the input using the given processor.
func process(proc *OutputProcessor, v interface{}) string {
	theCopy, err := proc.Process(v)
	if err != nil {
		logrus.Fatalf("Error processing: %v", err)
	}
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

func diff(oldFile string, newFile string) string {
	cmd := exec.Command("diff", oldFile, newFile)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		logrus.Warnf("Error running diff: %v", err)
	}
	return out.String()
}

func fail(t *testing.T, id string, expected string, actual string) {
	t.Logf("%s: mismatch: expected %s, got %s", id, expected, actual)
	ioutil.WriteFile(id + "-expected.json", []byte(expected), 0)
	ioutil.WriteFile(id + "-actual.json", []byte(actual), 0)
	diffed := diff(id + "-expected.json", id + "-actual.json")
	ioutil.WriteFile(id + ".diff", []byte(diffed), 0)
	t.Errorf("%s mismatch", id)
}

func TestDiff(t *testing.T) {
	cmd := exec.Command("diff", "-u", "/c/Users/localadmin/old.txt", "/c/Users/localadmin/new.txt")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	fmt.Println("diff=[[" + out.String() + "]]")
	if err != nil {
		logrus.Fatalf("Error running diff: %v", err)
	}
}

// Test processing all of the different types, in verbose and default mode, in parallel.
func TestProcess(t *testing.T) {
	tests := map[string]Strippable{
		"flat":           getFlat("flat"),
		"deep":           getDeep("deep", 6),
		"deepAnon":       getDeepAnon("deepAnon", 6),
		"deepArray":      getDeepArray("deepArray", 6),
		"deepIface":      getDeepIface("deepIface", 6),
		"deepIfaceArray": getDeepIfaceArray("deepIfaceArray", 6),
		"deepIfaceSlice": getDeepIfaceSlice("deepIfaceSlice", 6),
		"deepSlice":      getDeepSlice("deepSlice", 6),
	}
	var done sync.WaitGroup
	done.Add(len(tests) * 2)
	for k, v := range tests {
		go func(k string, v Strippable) {
			defer done.Done()
			proc := NewOutputProcessor()
			proc.Verbose = true
			expectedVerbose := marshal(v)
			actualVerbose := process(proc, v)
			if expectedVerbose != actualVerbose {
				fail(t, k + "-verbose", expectedVerbose, actualVerbose)
			}
		}(k, v)
		go func(k string, v Strippable) {
			defer done.Done()
			expectedDefault := v.Stripped()
			actualDefault := process(NewOutputProcessor(), v)

			if expectedDefault != actualDefault {
				fail(t, k + "-default", expectedDefault, actualDefault)
			}
		}(k, v)
	}
	done.Wait()
}
