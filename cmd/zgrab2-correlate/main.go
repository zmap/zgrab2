// Command zgrab2-correlate reads `zgrab2 multiple` JSONL output (one
// processing.Grab record per line, combining msmq/msrpc/smb/rdp results per
// host) from stdin or --input, and writes one correlate.HostAssessment
// JSON object per line to stdout or --output.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zmap/zgrab2/correlate"
)

func main() {
	input := flag.String("input", "-", "Input filename, use - for stdin")
	output := flag.String("output", "-", "Output filename, use - for stdout")
	flag.Parse()

	in, err := openInput(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zgrab2-correlate: %v\n", err)
		os.Exit(1)
	}
	defer in.Close()

	out, err := openOutput(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zgrab2-correlate: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	if err := run(in, out); err != nil {
		fmt.Fprintf(os.Stderr, "zgrab2-correlate: %v\n", err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	encoder := json.NewEncoder(out)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		assessment, err := correlate.AssessHost(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "zgrab2-correlate: line %d: %v\n", lineNum, err)
			continue
		}
		if err := encoder.Encode(assessment); err != nil {
			return fmt.Errorf("writing output at line %d: %w", lineNum, err)
		}
	}
	return scanner.Err()
}

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening input %q: %w", path, err)
	}
	return f, nil
}

func openOutput(path string) (io.WriteCloser, error) {
	if path == "-" {
		return nopWriteCloser{os.Stdout}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("opening output %q: %w", path, err)
	}
	return f, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
