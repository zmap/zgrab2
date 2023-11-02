package http

import (
	"io"

	"golang.org/x/net/html"
)

type htmlParser struct {
	tokenizer         *html.Tokenizer
	tags              map[string]struct{}
	attributesParsers map[string]attributesParser
}

type attributesParser struct {
	fieldIndicators        fieldIndicators
	attributeKeysWithValue []string
}

type fieldIndicators struct {
	attributeKeys   map[string]struct{}
	attributeValues map[string]struct{}
}

type htmlParserResult struct {
	tags   map[string]string
	fields map[string][]string
}

func (p htmlParser) parseHTML() htmlParserResult {
	result := htmlParserResult{
		tags:   make(map[string]string, 0),
		fields: make(map[string][]string, 0),
	}

	for {
		tokenType := p.tokenizer.Next()

		switch tokenType {
		default:
			continue
		case html.ErrorToken:
			if p.tokenizer.Err() == io.EOF {
				return result
			}
			continue
		case html.StartTagToken, html.SelfClosingTagToken:
			tagName, hasAttributes := p.tokenizer.TagName()
			tagNameString := string(tagName)
			if _, ok := p.tags[tagNameString]; ok {
				if tokenType = p.tokenizer.Next(); tokenType == html.TextToken {
					result.tags[tagNameString] = string(p.tokenizer.Text())
				}
				continue
			}

			if !hasAttributes {
				continue
			}

			var (
				foundFieldNames  = make(map[string]struct{}, 0)
				foundFieldValues = make(map[string]string, 0)
			)
			for {
				attributeKey, attributeValue, hasMoreAttributes := p.tokenizer.TagAttr()

				for fieldName, attributeParser := range p.attributesParsers {
					if len(attributeParser.fieldIndicators.attributeKeys) > 0 {
						if _, ok := attributeParser.fieldIndicators.attributeKeys[string(attributeKey)]; !ok {
							continue
						}
						if _, ok := attributeParser.fieldIndicators.attributeValues[string(attributeValue)]; !ok {
							continue
						}
					}

					foundFieldNames[fieldName] = struct{}{}
				}

				foundFieldValues[string(attributeKey)] = string(attributeValue)

				if !hasMoreAttributes {
					for foundFieldName := range foundFieldNames {
						parser := p.attributesParsers[foundFieldName]
						if len(parser.attributeKeysWithValue) > 0 {
							for _, attributeKeyWithValue := range parser.attributeKeysWithValue {
								if value := foundFieldValues[attributeKeyWithValue]; value != "" {
									result.fields[foundFieldName] = append(result.fields[foundFieldName], value)
								}
							}
						}
					}
					break
				}
			}
		}
	}
}
