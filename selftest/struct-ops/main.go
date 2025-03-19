package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"encoding/binary"
	"unsafe"

	bpf "github.com/khulnasoft-lab/libbpfgo"
)

// endian returns the system's byte order by examining the memory layout of a fixed int32 value.
// It stores 0x01020304 in memory and inspects its first byte: if the byte equals 0x04, it returns
// binary.LittleEndian; otherwise, it returns binary.BigEndian.
func endian() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// main is the entry point that loads the BPF module from "main.bpf.o", attaches struct operations for maps of type BPF_MAP_TYPE_STRUCT_OPS, and spawns a goroutine to periodically log local and global statistics from the "stats" map. It listens for termination signals to gracefully cancel operations, clean up resources, and exit the program.
func main() {
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath:     "main.bpf.o",
		KernelLogLevel: 0,
	})
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		os.Exit(-1)
	}

	m := bpfModule

	var afterFunc func()

	iters := m.Iterator()
	for {
		m := iters.NextMap()
		if m == nil {
			break
		}
		if m.Type().String() == "BPF_MAP_TYPE_STRUCT_OPS" {
			var link *bpf.BPFLink
			if link, err = m.AttachStructOps(); err != nil {
				log.Printf("error: %v", err)
				os.Exit(-1)
			}
			afterFunc = func() {
				if err := link.Destroy(); err != nil {
					log.Printf("error: %v", err)
					os.Exit(-1)
				}
			}
		}
	}

	var statsMap *bpf.BPFMap
	if statsMap, err = bpfModule.GetMap("stats"); err != nil {
		log.Printf("error: %v", err)
		os.Exit(-1)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	wg.Add(1)
	go func(ctx context.Context) {
		for true {
			select {
			case <-ctx.Done():
				wg.Done()
				return
			default:
				res := getStat(statsMap)
				log.Printf("local: %d, global: %d", res[0], res[1])
			}
			time.Sleep(1 * time.Second)
		}
	}(ctx)
	time.Sleep(3 * time.Second)
	cancel()
	wg.Wait()
	afterFunc()
	log.Println("scheduler exit")
	os.Exit(0)
}

// getStat retrieves and aggregates per-CPU counter statistics from the provided BPF map.
// It queries the map for two specific keys (0 and 1), converts the per-CPU raw byte data to uint64 values
// based on the system's endianness, and sums the counts for each key.
// The returned slice contains the aggregated counts for the two indices.
// The function logs a fatal error and terminates the program if it fails to determine the CPU count or retrieve a map value.
func getStat(m *bpf.BPFMap) []uint64 {
	cpuNum, err := bpf.NumPossibleCPUs()
	if err != nil {
		log.Fatal(err)
	}
	cnts := make([][]uint64, 2)
	cnts[0] = make([]uint64, cpuNum)
	cnts[1] = make([]uint64, cpuNum)
	stats := []uint64{0, 0}
	for i := 0; i < 2; i++ {
		v, err := m.GetValue(unsafe.Pointer(&i))
		if err != nil {
			log.Fatal(err)
		}
		for cpu := 0; cpu < cpuNum; cpu++ {
			n := v[cpu*8 : cpu*8+8]
			cnts[i][cpu] = endian().Uint64(n)
			stats[i] += cnts[i][cpu]
		}
	}
	return stats
}
