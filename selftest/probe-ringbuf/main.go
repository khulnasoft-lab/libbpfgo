package main

import "C"

import (
	"fmt"
	"os"

	bpf "github.com/khulnasoft-lab/libbpfgo"
)

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
	rb, err := bpfModule.InitRingBuf("events1", eventsChannel1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer rb.Close()

	rb.Start()

	// Process events for a short time or until a condition is met
	// This could be a time-based loop, a signal handler, or other mechanism
	for i := 0; i < 10; i++ {
		event := <-eventsChannel1
		fmt.Printf("Received event: %v\n", event)
	}

	// Or use a select with a timeout
	timeout := time.After(5 * time.Second)
	select {
	case event := <-eventsChannel1:
		fmt.Printf("Received event: %v\n", event)
	case <-timeout:
		fmt.Println("Timeout waiting for events")
	}
}
