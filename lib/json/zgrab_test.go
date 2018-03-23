package json

import (
	"bytes"
	"encoding/json"
	"log"
	"testing"
)

type Flat struct {
	Always        string `json:"always"`
	NotEmpty      string `json:"not_empty,omitempty"`
	Debug         string `json:"debug" zgrab:"debug"`
	DebugNotEmpty string `json:"debug_not_empty,omitempty" zgrab:"debug"`
}

type FakeFlat struct {
	Always        string `json:"always"`
	NotEmpty      string `json:"not_empty,omitempty"`
	Debug         string `json:"debug,omitempty" zgrab:"debug"`
	DebugNotEmpty string `json:"debug_not_empty,omitempty" zgrab:"debug"`
}

func TestFlat(t *testing.T) {
	abcd := Flat{Always: "a", NotEmpty: "b", Debug: "c", DebugNotEmpty: "d"}
	abc_ := Flat{Always: "a", NotEmpty: "b", Debug: "c"}
	ab_d := Flat{Always: "a", NotEmpty: "b", Debug: "", DebugNotEmpty: "d"}
	ab__ := Flat{Always: "a", NotEmpty: "b"}
	a_cd := Flat{Always: "a", NotEmpty: "", Debug: "c", DebugNotEmpty: "d"}
	a_c_ := Flat{Always: "a", NotEmpty: "", Debug: "c"}
	a__d := Flat{Always: "a", NotEmpty: "", Debug: "", DebugNotEmpty: "d"}
	a___ := Flat{Always: "a"}
	_bcd := Flat{Always: "", NotEmpty: "b", Debug: "c", DebugNotEmpty: "d"}
	_bc_ := Flat{Always: "", NotEmpty: "b", Debug: "c"}
	_b_d := Flat{Always: "", NotEmpty: "b", Debug: "", DebugNotEmpty: "d"}
	_b__ := Flat{Always: "", NotEmpty: "b"}
	__cd := Flat{Debug: "c", DebugNotEmpty: "d"}
	__c_ := Flat{Debug: "c"}
	___d := Flat{Debug: "d"}
	empty := Flat{}
	var nonDebug = map[Flat]FakeFlat{
		abcd:  FakeFlat(ab__),
		abc_:  FakeFlat(ab__),
		ab_d:  FakeFlat(ab__),
		ab__:  FakeFlat(ab__),
		a_cd:  FakeFlat(a___),
		a_c_:  FakeFlat(a___),
		a__d:  FakeFlat(a___),
		a___:  FakeFlat(a___),
		_bcd:  FakeFlat(_b__),
		_bc_:  FakeFlat(_b__),
		_b_d:  FakeFlat(_b__),
		_b__:  FakeFlat(_b__),
		__cd:  FakeFlat(empty),
		__c_:  FakeFlat(empty),
		___d:  FakeFlat(empty),
		empty: FakeFlat(empty),
	}
	for input, expected := range nonDebug {
		actual, err := Marshal(input, false)
		if err != nil {
			log.Fatalf("Unexpected error encoding JSON: %v", err)
		}
		ex, err := json.Marshal(expected)
		if err != nil {
			log.Fatalf("Unexpected error encoding JSON: %v", err)
		}
		if !bytes.Equal(actual, ex) {
			t.Errorf("Non-debug mismatch: expected %s, got %s", string(ex), string(actual))
		}
	}
	for input := range nonDebug {
		actual, err := Marshal(input, true)
		if err != nil {
			log.Fatalf("Unexpected error encoding JSON: %v", err)
		}
		ex, err := json.Marshal(input)
		if err != nil {
			log.Fatalf("Unexpected error encoding JSON: %v", err)
		}
		if !bytes.Equal(actual, ex) {
			t.Errorf("debug mismatch: expected %s, got %s", string(ex), string(actual))
		}
	}
}

type Leaf struct {
	A string `json:"a"`
	B string `json:"b" zgrab:"debug"`
}

type Intermediate struct {
	A Leaf `json:"a"`
	B Leaf `json:"b" zgrab:"debug"`
	C string `json:"c"`
	D string `json:"d" zgrab:"debug"`
}

type Nested struct {
	A Intermediate `json:"a"`
	B Intermediate `json:"b" zgrab:"debug"`
	C Leaf `json:"c"`
	D Leaf `json:"d" zgrab:"debug"`
	E string `json:"e"`
	F string `json:"f" zgrab:"debug"`
}

type dict map[string]interface{}

func TestNested(t *testing.T) {
	input := Nested{
		A: Intermediate{
			A: Leaf{A:"aaa", B:"aab"},
			B: Leaf{A:"aba", B:"abb"},
			C: "ac",
			D: "ad",
		},
		B: Intermediate{
			A: Leaf{A:"baa", B:"bab"},
			B: Leaf{A:"bba", B:"bbb"},
			C: "bc",
			D: "bd",
		},
		C: Leaf{A:"ca", B:"cb"},
		D: Leaf{A:"da", B:"db"},
		E: "e",
		F: "f",
	}
	expected:= dict{
		"a": dict{
			"a": dict{"a":"aaa"},
			"c": "ac",
		},
		"c": dict{"a":"ca"},
		"e": "e",
	}
	nonDebugActual, err := Marshal(input, false)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	nonDebugEx, err := json.Marshal(expected)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	if !bytes.Equal(nonDebugActual, nonDebugEx) {
		t.Errorf("Non-debug mismatch: expected %s, got %s", string(nonDebugEx), string(nonDebugActual))
	}
	debugActual, err := Marshal(input, true)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	debugEx, err := json.Marshal(input)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	if !bytes.Equal(debugActual, debugEx) {
		t.Errorf("Debug mismatch: expected %s, got %s", string(debugEx), string(debugActual))
	}
}

type Bogus struct {
	A string `json:"a" zgrab:"unknown,debug,somethingelse"`
	B string `json:"b" zgrab:"notdebug"`
}

func TestBogus(t *testing.T) {
	input := Bogus{
		A:"a",
		B:"b",
	}
	expected:= dict{"b":"b"}
	nonDebugActual, err := Marshal(input, false)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	nonDebugEx, err := json.Marshal(expected)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	if !bytes.Equal(nonDebugActual, nonDebugEx) {
		t.Errorf("Non-debug mismatch: expected %s, got %s", string(nonDebugEx), string(nonDebugActual))
	}
	debugActual, err := Marshal(input, true)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	debugEx, err := json.Marshal(input)
	if err != nil {
		log.Fatalf("Unexpected error encoding JSON: %v", err)
	}
	if !bytes.Equal(debugActual, debugEx) {
		t.Errorf("Debug mismatch: expected %s, got %s", string(debugEx), string(debugActual))
	}
}