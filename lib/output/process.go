// Package output contains utilities for processing results from zgrab2 scanners
// for eventual output and consumption by ztag.
package output

import (
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
)

// ZGrabTag holds the information from the `zgrab` tag. Currently only supports
// the zgrab tag.
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

// Check if the type is primitive, or eventually points to a primitive type.
func isPrimitiveType(what reflect.Type) bool {
	return isPrimitiveKind(dereferenceType(what).Kind())
}

// Types that are considered to be non-primitive
var compoundKinds = map[reflect.Kind]bool{
	reflect.Struct:    true,
	reflect.Slice:     true,
	reflect.Array:     true,
	reflect.Map:       true,
	reflect.Interface: true,
}

// Get the eventual type for JSON-encoding purposes
func dereferenceType(what reflect.Type) reflect.Type {
	for ; what.Kind() == reflect.Ptr; what = what.Elem() {
	}
	return what
}

// Check if the kind is primitive
func isPrimitiveKind(kind reflect.Kind) bool {
	ret, ok := compoundKinds[kind]
	return !(ret && ok)
}

// OutputProcessor holds the options and state for a processing run.
type OutputProcessor struct {
	// Verbose indicates that debug fields should not be stripped out.
	Verbose bool
}

// NewOutputProcessor gets a new OutputProcessor with the default settings.
func NewOutputProcessor() *OutputProcessor {
	return &OutputProcessor{
		Verbose: false,
	}
}

// Process the input using the options in the given OutputProcessor.
func (processor *OutputProcessor) Process(v interface{}) (interface{}, error) {
	ret, err := processor.process(v)
	if err != nil {
		return nil, err
	}
	return ret.Interface(), nil
}

// Process the input using the default options (strip debug fields).
func Process(v interface{}) (interface{}, error) {
	return NewOutputProcessor().Process(v)
}

// Internal version to catch panics
func (processor *OutputProcessor) process(v interface{}) (ret reflect.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			if s, ok := r.(string); ok {
				panic(s)
			}
			ret = reflect.ValueOf(nil)
			err = r.(error)
		}
	}()
	return processor.processValue(reflect.ValueOf(&v).Elem()), nil
}

// Handle an error
func (processor *OutputProcessor) error(err error) {
	panic(err)
}

// Process the given value, returning the processed copy.
func (processor *OutputProcessor) processValue(v reflect.Value) reflect.Value {
	return valueProcessor(v)(processor, v)
}

// processorFunc takes an OutputProcessor and a value, and returns a processed copy of the value.
type processorFunc func(s *OutputProcessor, v reflect.Value) reflect.Value

// processorCache maps reflect.Type to processorFunc, and caches the processors
// for the various types.
var processorCache sync.Map

// valueProcessor gets a processorFunc for the given actual value.
func valueProcessor(v reflect.Value) processorFunc {
	if !v.IsValid() {
		return dupeProcessor
	}
	return typeProcessor(v.Type())
}

// typeProcessor gets (potentially cached) a processorFunc for the given type.
func typeProcessor(t reflect.Type) processorFunc {
	if fi, ok := processorCache.Load(t); ok {
		return fi.(processorFunc)
	}

	// To deal with recursive types, populate the map with an
	// indirect func before we build it. This type waits on the
	// real func (f) to be ready and then calls it. This indirect
	// func is only used for recursive types.
	var (
		wg sync.WaitGroup
		f  processorFunc
	)
	wg.Add(1)
	fi, loaded := processorCache.LoadOrStore(t, processorFunc(func(processor *OutputProcessor, v reflect.Value) reflect.Value {
		wg.Wait()
		return f(processor, v)
	}))
	if loaded {
		return fi.(processorFunc)
	}

	// Compute the real processor and replace the indirect func with it.
	f = newTypeProcessor(t)
	wg.Done()
	processorCache.Store(t, f)

	return f
}

// newTypeProcessor constructs a processorFunc for a type.
func newTypeProcessor(t reflect.Type) processorFunc {
	switch t.Kind() {
	case reflect.Interface:
		return interfaceProcessor
	case reflect.Struct:
		return newStructProcessor(t)
	case reflect.Map:
		return newMapProcessor(t)
	case reflect.Slice:
		return newSliceProcessor(t)
	case reflect.Array:
		return newArrayProcessor(t)
	case reflect.Ptr:
		return newPtrProcessor(t)
	default:
		return dupeProcessor
	}
}

// dupeProcessor is a processorFunc that returns a plain duplicate of the given
// (hopefully primitive) value.
func dupeProcessor(_ *OutputProcessor, v reflect.Value) reflect.Value {
	ret := reflect.New(v.Type()).Elem()
	ret.Set(v)
	return ret
}

// interfaceProcessor returns a processor for the value underlying the interface.
func interfaceProcessor(processor *OutputProcessor, v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.New(v.Type()).Elem() // nil
	}
	// FIXME: re-wrap in interface{}?
	ret := processor.processValue(v.Elem())
	return ret
}

// structProcessor holds the state for processing a single struct type.
type structProcessor struct {
	// what is the type being processed.
	what reflect.Type

	// fields contain the needed information to identify / locate / read / set
	// the value of the field on an instance of the struct.
	fields []field

	// fieldEncs are the processorFuncs for the associated fields.
	fieldEncs []processorFunc
}

// structProcessor.process processes each field in se.fields (unless omitted).
func (se *structProcessor) process(processor *OutputProcessor, v reflect.Value) reflect.Value {
	ret := reflect.New(v.Type()).Elem()
	for i, f := range se.fields {
		fv := fieldByIndex(v, f.index)
		if !fv.IsValid() {
			// e.g. it's a field inside a null pointer
			continue
		}

		if f.zgrabTag.Debug && !processor.Verbose {
			// ignore
		} else {
			// get output field
			rfv := writableFieldByIndex(ret, f.index)
			if rfv.CanSet() {
				// set output field to processed value
				rfv.Set(se.fieldEncs[i](processor, fv))
			} else {
				logrus.Warnf("zgrab output process: Cannot copy over field %s (%v)", f.name, rfv)
			}
		}
	}
	return ret
}

// newStructProcessor constructs a processor for the struct.
func newStructProcessor(t reflect.Type) processorFunc {
	fields := cachedTypeFields(t)
	se := &structProcessor{
		what:      t,
		fields:    fields,
		fieldEncs: make([]processorFunc, len(fields)),
	}
	for i, f := range fields {
		se.fieldEncs[i] = typeProcessor(typeByIndex(t, f.index))
	}
	return se.process
}

// mapProcessor holds the state for a specific type of map processor.
type mapProcessor struct {
	elemEnc processorFunc
}

// mapProcessor.process processes the given compound map type -- processes each
// value and returns a copy of it.
func (me *mapProcessor) process(processor *OutputProcessor, v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.New(v.Type()).Elem() // nil
	}
	// As with slices, the value returned by MakeMap cannot be set / addressed.
	// So, we make a pointer to the map, then store the map in the pointer.
	ret := reflect.New(v.Type()).Elem()
	ret.Set(reflect.MakeMap(v.Type()))

	keys := v.MapKeys()
	sv := make([]reflectWithString, len(keys))
	for i, v := range keys {
		sv[i].v = v
		if err := sv[i].resolve(); err != nil {
			processor.error(err)
		}
	}

	for _, kv := range sv {
		ret.SetMapIndex(kv.v, me.elemEnc(processor, v.MapIndex(kv.v)))
	}
	return ret
}

// newMapProcessor constructs a map processor for the given map type; primitive
// types are just duplicated, while compound types get special handling.
func newMapProcessor(t reflect.Type) processorFunc {
	if isPrimitiveType(t.Elem()) {
		return dupeProcessor
	}
	me := &mapProcessor{typeProcessor(t.Elem())}

	return me.process
}

// sliceProcessor just wraps an arrayProcessor, checking to make sure the value isn't nil.
type sliceProcessor struct {
	arrayEnc processorFunc
}

// sliceProcessor.process just wraps the equivalent arrayProcessor.
func (se *sliceProcessor) process(processor *OutputProcessor, v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.New(v.Type()).Elem() // nil
	}
	ret := se.arrayEnc(processor, v)
	return ret
}

// newSliceProcessor constructs a slice processorFunc -- for primitive types,
// just duplicates the slice, while compound types get special handling.
func newSliceProcessor(t reflect.Type) processorFunc {
	if isPrimitiveType(t.Elem()) {
		return dupeProcessor
	}
	enc := &sliceProcessor{newArrayProcessor(t)}
	return enc.process
}

// arrayProcessor calls the elemEnc for each element of the array (or slice).
type arrayProcessor struct {
	elemEnc processorFunc
}

// arrayProcessor.process creates a new slice/array, then calls the element
// processor on each element.
func (ae *arrayProcessor) process(processor *OutputProcessor, v reflect.Value) reflect.Value {
	n := v.Len()
	var ret reflect.Value
	if v.Kind() == reflect.Slice {
		// You cannot call Set() or Addr() on the slice directly; so we create
		// the pointer to the slice, and then set ret = *ptr = make([]type, n, cap)
		ret = reflect.New(v.Type()).Elem()
		ret.Set(reflect.MakeSlice(v.Type(), n, v.Cap()))
	} else {
		ret = reflect.New(v.Type()).Elem()
	}
	for i := 0; i < n; i++ {
		ret.Index(i).Set(ae.elemEnc(processor, v.Index(i)))
	}
	return ret
}

// newArrayProcessor constructs a new processorFunc
func newArrayProcessor(t reflect.Type) processorFunc {
	if isPrimitiveType(t.Elem()) {
		return dupeProcessor
	}
	enc := &arrayProcessor{typeProcessor(t.Elem())}
	return enc.process
}

// ptrProcessor wraps the state for processing a single pointer type
type ptrProcessor struct {
	elemEnc processorFunc
}

// ptrProcessor.process creates a new pointer then uses the element processor to full it.
func (pe *ptrProcessor) process(processor *OutputProcessor, v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.New(v.Type()).Elem() // nil
	}
	// type = *elem
	// ret = new(type) = new(*elem)
	ret := reflect.New(v.Type()).Elem()
	child := pe.elemEnc(processor, v.Elem())
	// *ret = &child
	ret.Set(child.Addr())
	return ret
}

// newPtrProcessor constructs a processorFunc for the given pointer type.
func newPtrProcessor(t reflect.Type) processorFunc {
	enc := &ptrProcessor{typeProcessor(t.Elem())}
	return enc.process
}

// isValidJSONNameTag checks if the `json` tag is a valid field name.
func isValidJSONNameTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but
			// otherwise any punctuation chars are allowed
			// in a tag name.
		default:
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
				return false
			}
		}
	}
	return true
}

// fieldByIndex gets the field of value with the given "index" (which is
// actually a sequence of indexes).
func fieldByIndex(v reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return reflect.Value{}
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}
	return v
}

// Since a class's "fields" may actually be fields of its anonymous member
// structs, and some of these may include pointers, instantiate any nils along
// the way (as such, this should only be called if it is really gointg to be
// written).
func writableFieldByIndex(v reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}
	return v
}

// typeByIndex gets the type of the field with the given "index"
func typeByIndex(t reflect.Type, index []int) reflect.Type {
	for _, i := range index {
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		t = t.Field(i).Type
	}
	return t
}

// reflectWithString gets the string version of the given value (for use as a
// key value)
type reflectWithString struct {
	v reflect.Value
	s string
}

func (w *reflectWithString) resolve() error {
	if w.v.Kind() == reflect.String {
		w.s = w.v.String()
		return nil
	}
	switch w.v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.s = strconv.FormatInt(w.v.Int(), 10)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		w.s = strconv.FormatUint(w.v.Uint(), 10)
		return nil
	}
	panic("unexpected map key type")
}

// A field represents a single field found in a struct.
type field struct {
	name      string
	nameBytes []byte                 // []byte(name)
	equalFold func(s, t []byte) bool // bytes.EqualFold or equivalent

	parent   reflect.Type
	tag      bool
	index    []int
	typ      reflect.Type
	zgrabTag ZGrabTag
}

// byIndex sorts field by index sequence.
type byIndex []field

// Len gets the length of the index sequence.
func (x byIndex) Len() int { return len(x) }

// Swap swaps the ith and jth indexes.
func (x byIndex) Swap(i, j int) { x[i], x[j] = x[j], x[i] }

// Less compares the ith and jth index
func (x byIndex) Less(i, j int) bool {
	for k, xik := range x[i].index {
		if k >= len(x[j].index) {
			return false
		}
		if xik != x[j].index[k] {
			return xik < x[j].index[k]
		}
	}
	return len(x[i].index) < len(x[j].index)
}

// typeFields returns a list of fields that JSON should recognize for the given type.
// The algorithm is breadth-first search over the set of structs to include - the top struct
// and then any reachable anonymous structs.
func typeFields(t reflect.Type) []field {
	// Anonymous fields to explore at the current level and the next.
	current := []field{}
	next := []field{{typ: t, parent: t}}

	// Count of queued names for current level and the next.
	count := map[reflect.Type]int{}
	nextCount := map[reflect.Type]int{}

	// Types already visited at an earlier level.
	visited := map[reflect.Type]bool{}

	// Fields found.
	var fields []field

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		for _, f := range current {
			if visited[f.typ] {
				continue
			}
			visited[f.typ] = true

			// Scan f.typ for fields to include.
			for i := 0; i < f.typ.NumField(); i++ {
				sf := f.typ.Field(i)
				if sf.Anonymous {
					t := sf.Type
					if t.Kind() == reflect.Ptr {
						t = t.Elem()
					}
					// If embedded, StructField.PkgPath is not a reliable
					// indicator of whether the field is exported.
					// See https://golang.org/issue/21122
					if !isExported(t.Name()) && t.Kind() != reflect.Struct {
						// Ignore embedded fields of unexported non-struct types.
						// Do not ignore embedded fields of unexported struct types
						// since they may have exported fields.
						continue
					}
				} else if sf.PkgPath != "" {
					// Ignore unexported non-embedded fields.
					continue
				}
				tag := sf.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name := strings.SplitN(tag, ",", 2)[0]
				if !isValidJSONNameTag(name) {
					name = ""
				}
				index := make([]int, len(f.index)+1)
				copy(index, f.index)
				index[len(f.index)] = i

				ft := sf.Type
				if ft.Name() == "" && ft.Kind() == reflect.Ptr {
					// Follow pointer.
					ft = ft.Elem()
				}

				// Record found field and index sequence.
				if name != "" || !sf.Anonymous || ft.Kind() != reflect.Struct {
					tagged := name != ""
					if name == "" {
						name = sf.Name
					}
					fields = append(fields, field{
						name:     name,
						tag:      tagged,
						index:    index,
						typ:      ft,
						parent:   t,
						zgrabTag: *parseZGrabTag(sf.Tag.Get("zgrab")),
					})
					if count[f.typ] > 1 {
						// If there were multiple instances, add a second,
						// so that the annihilation code will see a duplicate.
						// It only cares about the distinction between 1 or 2,
						// so don't bother generating any more copies.
						fields = append(fields, fields[len(fields)-1])
					}
					continue
				}

				// Record new anonymous struct to explore in next round.
				nextCount[ft]++
				if nextCount[ft] == 1 {
					next = append(next, field{name: ft.Name(), index: index, typ: ft, parent: t})
				}
			}
		}
	}

	sort.Slice(fields, func(i, j int) bool {
		x := fields
		// sort field by name, breaking ties with depth, then
		// breaking ties with "name came from json tag", then
		// breaking ties with index sequence.
		if x[i].name != x[j].name {
			return x[i].name < x[j].name
		}
		if len(x[i].index) != len(x[j].index) {
			return len(x[i].index) < len(x[j].index)
		}
		if x[i].tag != x[j].tag {
			return x[i].tag
		}
		return byIndex(x).Less(i, j)
	})

	// Delete all fields that are hidden by the Go rules for embedded fields,
	// except that fields with JSON tags are promoted.

	// The fields are sorted in primary order of name, secondary order
	// of field index length. Loop over names; for each name, delete
	// hidden fields by choosing the one dominant field that survives.
	out := fields[:0]
	for advance, i := 0, 0; i < len(fields); i += advance {
		// One iteration per name.
		// Find the sequence of fields with the name of this first field.
		fi := fields[i]
		name := fi.name
		for advance = 1; i+advance < len(fields); advance++ {
			fj := fields[i+advance]
			if fj.name != name {
				break
			}
		}
		if advance == 1 { // Only one field with this name
			out = append(out, fi)
			continue
		}
		dominant, ok := dominantField(fields[i : i+advance])
		if ok {
			out = append(out, dominant)
		}
	}

	fields = out
	sort.Sort(byIndex(fields))

	return fields
}

// isExported reports whether the identifier is exported.
func isExported(id string) bool {
	r, _ := utf8.DecodeRuneInString(id)
	return unicode.IsUpper(r)
}

// dominantField looks through the fields, all of which are known to
// have the same name, to find the single field that dominates the
// others using Go's embedding rules, modified by the presence of
// JSON tags. If there are multiple top-level fields, the boolean
// will be false: This condition is an error in Go and we skip all
// the fields.
func dominantField(fields []field) (field, bool) {
	// The fields are sorted in increasing index-length order. The winner
	// must therefore be one with the shortest index length. Drop all
	// longer entries, which is easy: just truncate the slice.
	length := len(fields[0].index)
	tagged := -1 // Index of first tagged field.
	for i, f := range fields {
		if len(f.index) > length {
			fields = fields[:i]
			break
		}
		if f.tag {
			if tagged >= 0 {
				// Multiple tagged fields at the same level: conflict.
				// Return no field.
				return field{}, false
			}
			tagged = i
		}
	}
	if tagged >= 0 {
		return fields[tagged], true
	}
	// All remaining fields have the same length. If there's more than one,
	// we have a conflict (two fields named "X" at the same level) and we
	// return no field.
	if len(fields) > 1 {
		return field{}, false
	}
	return fields[0], true
}

var fieldCache struct {
	value atomic.Value // map[reflect.Type][]field
	mu    sync.Mutex   // used only by writers
}

// cachedTypeFields is like typeFields but uses a cache to avoid repeated work.
func cachedTypeFields(t reflect.Type) []field {
	m, _ := fieldCache.value.Load().(map[reflect.Type][]field)
	f := m[t]
	if f != nil {
		return f
	}

	// Compute fields without lock.
	// Might duplicate effort but won't hold other computations back.
	f = typeFields(t)
	if f == nil {
		f = []field{}
	}

	fieldCache.mu.Lock()
	m, _ = fieldCache.value.Load().(map[reflect.Type][]field)
	newM := make(map[reflect.Type][]field, len(m)+1)
	for k, v := range m {
		newM[k] = v
	}
	newM[t] = f
	fieldCache.value.Store(newM)
	fieldCache.mu.Unlock()
	return f
}
