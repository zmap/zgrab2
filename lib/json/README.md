# Modified ZGrab JSON Marshaler #

## Usage:

When writing a module, debug fields need only be marked with the new
tag, `zgrab:"debug"`. The zgrab2 framework will use the new encoder to
get the right output.

If you need to get JSON with the debug fields stripped, you can call
the new `Marshal()` methods directly; they work the same as the standard
functions, except they take an extra final boolean parameter: when 
false, the `zgrab:"debug"` fields will be omitted. Otherwise, it acts
exactly as the standard JSON marshaller.

### Example

```golang
import "github.com/zmap/zgrab2/lib/json"
// ...
type MyResult struct {
  ImporantString string       `json:"important_value,omitempty"`
  ImportantInt int            `json:"important_int"`
  LessImportantValue string   `json:"less_important_value" zgrab:"debug"`
}

func dump(value *MyResult, includeDebugFields bool) string {
  output, err := json.MarshalIndent(value, "  ", "", includeDebugFields)
  if err != nil {
    panic(err)
  }
  return string(output)
}

```

## Notes and Caveats:

Since the `zgrab:"debug"` tag comes from the `struct` definition, if 
that information is not available -- for instance, because a custom 
`MarshalJSON()` function was used -- then this will not be able to 
process those tags.
Further, since the `MarshalJSON()` interface does not pass along the
`debug` value from the original call to `Marshal()`, it may not be
feasible to use debug-only fields inside custom-marshalled values.

## Source provenance and changes

The source was taken from go version 1.9, will the following changes:

  1. Removed testdata and bench_test.go.

  2. Added a new argument, `debug bool`, to `Marshal()` and `MarshalIndent()`
     in encode.go, which when false causes struct fields tagged with 
     `zgrab:"debug"` to be omitted.

      * Any other changes in encode.go beyond adding / forwarding the
        new parameter are marked with a `// JB 2018/03/23` comment.

  3. Updated all calls to `Marshal()` and `MarshalIndent()` in all files.
  
  4. Added zgrab_options.go, which holds the values parsed out of the
     zgrab tag (currently, only `zgrab:"debug"` is supported).

  5. Added zgrab_test.go, which confirms that debug fields are properly
     omitted.