package memcached

import "testing"

func TestSnakeToCamel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple_test", "SimpleTest"},
		{"another_example_here", "AnotherExampleHere"},
		{"test", "Test"},
		{"multiple_words_in_string", "MultipleWordsInString"},
		{"single", "Single"},
		{"", ""},
	}
	for _, test := range tests {
		result := SnakeToCamel(test.input)
		if result != test.expected {
			t.Errorf("snakeToCamel(%q) = %q; expected %q", test.input, result, test.expected)
		}
	}
}
