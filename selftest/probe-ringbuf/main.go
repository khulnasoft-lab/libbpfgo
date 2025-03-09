package main

import "C"

import (
	"fmt"
	"os"

	bpf "github.com/khulnasoft-lab/libbpfgo"
)

// Main is the entry point of the application. It loads a BPF module from "main.bpf.o", loads the BPF object,
// verifies that the ring buffer map type is supported (available from Linux kernel 5.8 onward),
// and initializes a ring buffer ("events1") with a channel for receiving event data.
// If any of these steps fail, the program logs the error to standard error and exits with a non-zero status.
func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// Should be supported from 5.8 onwards
	isSupported, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeRingbuf)
	if err != nil || !isSupported {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel1 := make(chan []byte)
	_, err = bpfModule.InitRingBuf("events1", eventsChannel1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}
