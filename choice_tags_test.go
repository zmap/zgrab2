package zgrab2_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestChoiceTagsDoNotContainCommas(t *testing.T) {
	invalidChoice := regexp.MustCompile(`choice:"[^"]*,[^"]*"|choice:"[^"]*"[[:space:]]*,`)
	fileSet := token.NewFileSet()

	err := filepath.WalkDir("modules", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(source, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok || field.Tag == nil {
				return true
			}
			tag, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				t.Errorf("%s: invalid struct tag: %v", fileSet.Position(field.Tag.Pos()), err)
			} else if invalidChoice.MatchString(tag) {
				t.Errorf("%s: comma in choice tag; use separate space-separated choice attributes: %s", fileSet.Position(field.Tag.Pos()), tag)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
