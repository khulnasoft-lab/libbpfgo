package main

import (
	"fmt"
	"os"

	bpf "github.com/khulnasoft-lab/libbpfgo"
)

// Main verifies that the BPF Ringbuf map type is not supported as expected (prior to Linux kernel 5.8).
// If the support check indicates that the Ringbuf is unexpectedly supported or returns no error,
// it prints an error message to standard error and exits with a non-zero status.
// Otherwise, it prints a confirmation that Ringbuf is not supported.
func main() {
	// Should not be supported before 5.8
	isSupported, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeRingbuf)
	if err == nil || isSupported {
		fmt.Fprintln(os.Stderr, "Ringbuf is supported unexpectedly or no error")
		os.Exit(-1)
	}

	fmt.Fprintln(os.Stdout, "Ringbuf is not supported as expected")
}
