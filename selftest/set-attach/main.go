package main

import "C"

import (
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"time"

	"fmt"

	bpf "github.com/khulnasoft-lab/libbpfgo"
)

// main sets up and attaches an eBPF program, then polls a ring buffer for events.
// It creates a BPF module from "main.bpf.o", retrieves the "foobar" program, and sets its expected attach type to BPFAttachTypeTraceFentry.
// The function configures the program’s attach target based on system architecture and verifies the auto-attach setting.
// After loading the BPF object and attaching the program, main initializes a ring buffer to collect events
// and spawns a goroutine to generate events. It continuously polls for events, validating that each contains the expected value,
// and exits on error or after receiving more than five valid events.
func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	prog, err := bpfModule.GetProgram("foobar")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// eBPF program type should only be set if it differs from the desired one
	// commit d6e6286a12e7 ("libbpf: disassociate section handler on explicit bpf_program__set_type() call")
	// err = prog.SetType(bpf.BPFProgTypeTracing)
	// if err != nil {
	//	 fmt.Fprintln(os.Stderr, err)
	//	 os.Exit(-1)
	// }
	err = prog.SetExpectedAttachType(bpf.BPFAttachTypeTraceFentry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	funcName := fmt.Sprintf("__%s_sys_mmap", ksymArch())
	err = prog.SetAttachTarget(0, funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// Test auto attach
	autoAttachOrig := prog.Autoattach()
	prog.SetAutoattach(!autoAttachOrig)
	if prog.Autoattach() == autoAttachOrig {
		fmt.Fprintln(os.Stderr, "set auto attach failed")
		os.Exit(-1)
	}
	prog.SetAutoattach(autoAttachOrig)

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	_, err = prog.AttachGeneric()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Poll(300)
	numberOfEventsReceived := 0
	go func() {
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
			time.Sleep(time.Second / 100)
		}
	}()
recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}
	rb.Stop()
	rb.Close()
}

func ksymArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported architecture")
	}
}
