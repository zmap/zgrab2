// Package output contains utilities for processing results from zgrab2 scanners
// for eventual output and consumption by ztag.
package output

import (
	"fmt"
	"reflect"
	"strings"
)

// ZGrabTag holds the information from the `zgrab` tag. Currently only supports
// the "debug" value.
type ZGrabTag struct {
	// Debug means that the field should only be output when doing verbose output.
	Debug bool
}

// parseZGrabTag reads the `zgrab` tag and returns the corresponding parsed
// ZGrabTag. Currently only "debug" is recognized; other options should be
// comma separated.
func parseZGrabTag(value string) *ZGrabTag {
	ret := ZGrabTag{Debug: false}
	fields := strings.Split(value, ",")
	for _, field := range fields {
		switch strings.TrimSpace(field) {
		case "debug":
			ret.Debug = true
		}
	}
	return &ret
}

// ProcessCallback is called for each element in a struct; if it returns
// a non-nil value, that value will be used and further processing on
// that element will be skipped.
type ProcessCallback func(*Processor, reflect.Value) *reflect.Value

type pathEntry struct {
	field string
	value reflect.Value
}

// Processor holds the state for a process run. A given processor should
// only be used on a single thread.
type Processor struct {
	// Callback is a function that gets called on each element being
	// processed. If the callback returns a non-nil value, that value is
	// returned immediately instead of doing any further processing on
	// the element.
	Callback ProcessCallback

	// Verbose determines whether `zgrab:"debug"` fields will be
	// included in the output.
	Verbose bool

	// Path is the current path being processed, from the root element.
	// Used for debugging purposes only.
	// If a panic occurs, the path will point to the element where the
	// element that caused the problem.
	Path []pathEntry
}

// NewProcessor returns a new Processor instance with the default settings.
func NewProcessor() *Processor {
	return &Processor{}
}

// getPath returns a string representation of the current path.
func (processor *Processor) getPath() string {
	ret := make([]string, len(processor.Path))
	for i, v := range processor.Path {
		ret[i] = v.field
	}
	return strings.Join(ret, "->")
}

// callback invokes the callback (or the default, if none is present).
// The callback can return an on-nil value to override the default behavior.
func (processor *Processor) callback(v reflect.Value) *reflect.Value {
	callback := processor.Callback
	if callback == nil {
		callback = NullProcessCallback
	}
	return callback(processor, v)
}

// NullProcessCallback is the default ProcessCallback; it just returns nil.
func NullProcessCallback(w *Processor, v reflect.Value) *reflect.Value {
	return nil
}

// duplicate a *primitive* value by doing a set-by-value (non-primitive values
// should not use this).
func (processor *Processor) duplicate(v reflect.Value) reflect.Value {
	ret := reflect.New(v.Type()).Elem()
	ret.Set(v)
	return ret
}

// Add a path with the given key and value to the stack.
func (processor *Processor) pushPath(key string, value reflect.Value) {
	processor.Path = append(processor.Path, pathEntry{
		field: key,
		value: value,
	})
}

// Get the most recent path entry.
func (processor *Processor) topPath() *pathEntry {
	return &processor.Path[len(processor.Path)-1]
}

// Remove the most recent entry from the stack (and return it).
func (processor *Processor) popPath() *pathEntry {
	ret := processor.topPath()
	processor.Path = processor.Path[0 : len(processor.Path)-1]
	return ret
}

// Helper to check if a value is nil. Non-nillable values are by definition
// not nil (though they may be "zero").
func isNil(v reflect.Value) bool {
	return (v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface || v.Kind() == reflect.Slice) && v.IsNil()
}

// Check if a field should be copied over to the return value.
// The only time a field should be wiped is if the field has the `zgrab:"debug"`
// tag set, and if the verbose flag is off.
// There is an additional caveat that, if the field is already nil, leave it
// (so that we don't set it to a non-nil "zero" value).
func (processor *Processor) shouldWipeField(parent reflect.Value, index int) bool {
	tField := parent.Type().Field(index)

	// Rather than zeroing out nil values, handle them at the outer level
	if isNil(parent.Field(index)) {
		//fmt.Printf("Bogus copy becase nil: %s (%#v) to zero\n", processor.getPath(), tField)
		return false
	}

	tag := parseZGrabTag(tField.Tag.Get("zgrab"))
	// The only time a field
	return tag.Debug && !processor.Verbose
}

// Process the struct instance.
func (processor *Processor) processStruct(v reflect.Value) reflect.Value {
	t := v.Type()
	ret := reflect.New(v.Type()).Elem()
	// Two possibilities:
	// (a) do ret.Set(v), then explicitly zero-out any debug fields.
	// (b) only copy over fields that are non-debug.
	// Going with (a)
	ret.Set(v)
	for i := 0; i < v.NumField(); i++ {
		tField := t.Field(i)
		field := v.Field(i)
		retField := ret.Field(i)
		if !retField.CanSet() {
			// skip non-exportable fields
			continue
		}
		if processor.shouldWipeField(v, i) {
			retField.Set(reflect.Zero(field.Type()))
			continue
		}
		processor.pushPath(fmt.Sprintf("%s(%d)", tField.Name, i), field)
		copy := processor.process(field)
		processor.popPath()
		retField.Set(copy)
	}
	return ret
}

// Process a pointer (make a new pointer pointing to a new copy of v's referent).
func (processor *Processor) processPtr(v reflect.Value) reflect.Value {
	ret := reflect.New(v.Type().Elem()).Elem()
	if v.IsNil() {
		//fmt.Println("Goodbye to ", processor.getPath())
		return ret.Addr()
	}
	processor.pushPath("*", v.Elem())
	copy := processor.process(v.Elem())
	processor.popPath()
	ret.Set(copy)
	return ret.Addr()
}

// Process an interface instance (make a new interface and point it to a copy of
// v's referent).
func (processor *Processor) processInterface(v reflect.Value) reflect.Value {
	ret := reflect.New(v.Type()).Elem()
	if v.IsNil() {
		return ret.Addr()
	}

	processor.pushPath("[interface:"+v.Type().Name()+")]", v.Elem())
	copy := processor.process(v.Elem())
	processor.popPath()
	ret.Set(copy)
	return ret
}

// Process a map -- copy over all keys and (copies of) values into a new map.
func (processor *Processor) processMap(v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.New(v.Type()).Elem() // nil
	}
	// As with slices, the value returned by MakeMap cannot be set / addressed.
	// So, we make a pointer to the map, then store the map in the pointer.
	ret := reflect.New(v.Type()).Elem()
	ret.Set(reflect.MakeMap(v.Type()))

	keys := v.MapKeys()

	for _, key := range keys {
		value := v.MapIndex(key)
		processor.pushPath(fmt.Sprintf("[%v]", key), value)
		copy := processor.process(value)
		processor.popPath()
		ret.SetMapIndex(key, copy)
	}
	return ret
}

// Process an array (add copies of each element into a new array).
func (processor *Processor) processArray(v reflect.Value) reflect.Value {
	ret := reflect.New(v.Type()).Elem()
	for i := 0; i < v.Len(); i++ {
		elt := v.Index(i)
		processor.pushPath(fmt.Sprintf("[%d]", i), elt)
		copy := processor.process(elt)
		ret.Index(i).Set(copy)
		processor.popPath()
	}
	return ret
}

// Return a copy of the given byte-slice-compatible value.
func (processor *Processor) copyByteSlice(v reflect.Value) reflect.Value {
	ret := reflect.New(v.Type()).Elem()
	ret.Set(reflect.MakeSlice(v.Type(), v.Len(), v.Cap()))
	reflect.Copy(ret, v)
	return ret
}

// Process a slice (add copies of each element into a new slice with the same
// length and capacity).
func (processor *Processor) processSlice(v reflect.Value) reflect.Value {
	if v.IsNil() {
		panic(fmt.Errorf("Slice %#v (%s) is nil?\n", v, processor.getPath()))
	}
	if v.Type().Elem().Kind() == reflect.Uint8 {
		return processor.copyByteSlice(v)
	}

	n := v.Len()
	ret := reflect.New(v.Type()).Elem()
	ret.Set(reflect.MakeSlice(v.Type(), n, v.Cap()))
	for i := 0; i < n; i++ {
		elt := v.Index(i)
		processor.pushPath(fmt.Sprintf("[%d]", i), elt)
		copy := processor.process(elt)
		ret.Index(i).Set(copy)
		processor.popPath()
	}
	return ret
}

// Process an arbitrary value. Invokes the processor's callback; if it returns
// a non-nil value, return that. Otherwise, continue recursively processing
// the value.
func (processor *Processor) process(v reflect.Value) reflect.Value {
	temp := processor.callback(v)
	if temp != nil {
		return *temp
	}
	if isNil(v) {
		// Just leave nil values alone.
		return v
	}

	t := v.Type()
	switch t.Kind() {
	case reflect.Struct:
		return processor.processStruct(v)
	case reflect.Ptr:
		return processor.processPtr(v)
	case reflect.Slice:
		return processor.processSlice(v)
	case reflect.Array:
		return processor.processArray(v)
	case reflect.Interface:
		return processor.processInterface(v)
	case reflect.Map:
		return processor.processMap(v)
	default:
		return processor.duplicate(v)
	}
}

// Process the given value recursively using the options in this processor.
func (processor *Processor) Process(v interface{}) (ret interface{}, err error) {
	defer func() {
		if thrown := recover(); thrown != nil {
			cast, ok := thrown.(error)
			if !ok {
				panic(thrown)
			}
			err = cast
			ret = nil
		}
	}()
	return processor.process(reflect.ValueOf(v)).Interface(), nil
}

// Process the given value recursively using the default options.
func Process(v interface{}) (interface{}, error) {
	return NewProcessor().Process(v)
}
