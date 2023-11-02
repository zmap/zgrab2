package http

import (
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func Test_htmlParser_parseHTML(t *testing.T) {
	testHTML := `<tag1>tagValue1</tag1><tag2>tagValue2</tag2>
					<attrs1 attr1=a1 val1=v1>
					<attrs2 val2=v2 attr2=a2>
					<attrs3 attr1=a2 val=v1>
					<attrs4 val=v2 attr2=a1>
					<attrs5 val=v3 attr3=a3>
					<attrs6 val66=v66 attr3=a3>`
	testErrHtml := `<tag1>tagValue1</tag1><t<t11></t11>><tag2>tagValue2</tag2>`

	type fields struct {
		tokenizer         *html.Tokenizer
		tags              map[string]struct{}
		attributesParsers map[string]attributesParser
	}
	tests := []struct {
		name   string
		fields fields
		want   htmlParserResult
	}{
		{
			name: "empty html",
			fields: fields{
				tokenizer:         html.NewTokenizer(strings.NewReader("")),
				tags:              nil,
				attributesParsers: nil,
			},
			want: htmlParserResult{
				tags:   make(map[string]string, 0),
				fields: make(map[string][]string, 0),
			},
		},
		{
			name: "only tag",
			fields: fields{
				tokenizer:         html.NewTokenizer(strings.NewReader(testHTML)),
				tags:              map[string]struct{}{"tag1": {}},
				attributesParsers: nil,
			},
			want: htmlParserResult{
				tags:   map[string]string{"tag1": "tagValue1"},
				fields: make(map[string][]string, 0),
			},
		},
		{
			name: "two tags",
			fields: fields{
				tokenizer:         html.NewTokenizer(strings.NewReader(testHTML)),
				tags:              map[string]struct{}{"tag1": {}, "tag2": {}},
				attributesParsers: nil,
			},
			want: htmlParserResult{
				tags:   map[string]string{"tag1": "tagValue1", "tag2": "tagValue2"},
				fields: make(map[string][]string, 0),
			},
		},
		{
			name: "tags and one field from attributes",
			fields: fields{
				tokenizer: html.NewTokenizer(strings.NewReader(testHTML)),
				tags:      map[string]struct{}{"tag1": {}, "tag2": {}},
				attributesParsers: map[string]attributesParser{
					"field1": {
						fieldIndicators: fieldIndicators{
							attributeKeys:   map[string]struct{}{"attr1": {}},
							attributeValues: map[string]struct{}{"a1": {}},
						},
						attributeKeysWithValue: []string{"val1"},
					},
				},
			},
			want: htmlParserResult{
				tags:   map[string]string{"tag1": "tagValue1", "tag2": "tagValue2"},
				fields: map[string][]string{"field1": {"v1"}},
			},
		},
		{
			name: "tags and one field from attributes in reverse order",
			fields: fields{
				tokenizer: html.NewTokenizer(strings.NewReader(testHTML)),
				tags:      map[string]struct{}{"tag1": {}, "tag2": {}},
				attributesParsers: map[string]attributesParser{
					"field2": {
						fieldIndicators: fieldIndicators{
							attributeKeys:   map[string]struct{}{"attr2": {}},
							attributeValues: map[string]struct{}{"a2": {}},
						},
						attributeKeysWithValue: []string{"val2"},
					},
				},
			},
			want: htmlParserResult{
				tags:   map[string]string{"tag1": "tagValue1", "tag2": "tagValue2"},
				fields: map[string][]string{"field2": {"v2"}},
			},
		},
		{
			name: "tags and fields from attributes",
			fields: fields{
				tokenizer: html.NewTokenizer(strings.NewReader(testHTML)),
				tags:      map[string]struct{}{"tag1": {}, "tag2": {}},
				attributesParsers: map[string]attributesParser{
					"field1": {
						fieldIndicators: fieldIndicators{
							attributeKeys:   map[string]struct{}{"attr1": {}, "attr2": {}},
							attributeValues: map[string]struct{}{"a1": {}, "a2": {}},
						},
						attributeKeysWithValue: []string{"val"},
					},
					"field2": {
						fieldIndicators: fieldIndicators{
							attributeKeys:   map[string]struct{}{},
							attributeValues: map[string]struct{}{},
						},
						attributeKeysWithValue: []string{"val", "val66"},
					},
				},
			},
			want: htmlParserResult{
				tags: map[string]string{"tag1": "tagValue1", "tag2": "tagValue2"},
				fields: map[string][]string{
					"field1": {"v1", "v2"},
					"field2": {"v1", "v2", "v3", "v66"},
				},
			},
		},
		{
			name: "error tag",
			fields: fields{
				tokenizer:         html.NewTokenizer(strings.NewReader(testErrHtml)),
				tags:              map[string]struct{}{"tag1": {}, "tag2": {}},
				attributesParsers: nil,
			},
			want: htmlParserResult{
				tags:   map[string]string{"tag1": "tagValue1", "tag2": "tagValue2"},
				fields: make(map[string][]string, 0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := htmlParser{
				tokenizer:         tt.fields.tokenizer,
				tags:              tt.fields.tags,
				attributesParsers: tt.fields.attributesParsers,
			}
			if got := p.parseHTML(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseHTML() = %v, want %v", got, tt.want)
			}
		})
	}
}
