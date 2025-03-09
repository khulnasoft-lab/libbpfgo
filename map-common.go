package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"syscall"
)

type MapType uint32

const (
	MapTypeUnspec MapType = iota
	MapTypeHash
	MapTypeArray
	MapTypeProgArray
	MapTypePerfEventArray
	MapTypePerCPUHash
	MapTypePerCPUArray
	MapTypeStackTrace
	MapTypeCgroupArray
	MapTypeLRUHash
	MapTypeLRUPerCPUHash
	MapTypeLPMTrie
	MapTypeArrayOfMaps
	MapTypeHashOfMaps
	MapTypeDevMap
	MapTypeSockMap
	MapTypeCPUMap
	MapTypeXSKMap
	MapTypeSockHash
	MapTypeCgroupStorage
	MapTypeReusePortSockArray
	MapTypePerCPUCgroupStorage
	MapTypeQueue
	MapTypeStack
	MapTypeSKStorage
	MapTypeDevmapHash
	MapTypeStructOps
	MapTypeRingbuf
	MapTypeInodeStorage
	MapTypeTaskStorage
	MapTypeBloomFilter
	MapTypeUserRingbuf
	MapTypeCgrpStorage
	MapTypeArena
)

var mapTypeToString = map[MapType]string{
	MapTypeUnspec:              "BPF_MAP_TYPE_UNSPEC",
	MapTypeHash:                "BPF_MAP_TYPE_HASH",
	MapTypeArray:               "BPF_MAP_TYPE_ARRAY",
	MapTypeProgArray:           "BPF_MAP_TYPE_PROG_ARRAY",
	MapTypePerfEventArray:      "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
	MapTypePerCPUHash:          "BPF_MAP_TYPE_PERCPU_HASH",
	MapTypePerCPUArray:         "BPF_MAP_TYPE_PERCPU_ARRAY",
	MapTypeStackTrace:          "BPF_MAP_TYPE_STACK_TRACE",
	MapTypeCgroupArray:         "BPF_MAP_TYPE_CGROUP_ARRAY",
	MapTypeLRUHash:             "BPF_MAP_TYPE_LRU_HASH",
	MapTypeLRUPerCPUHash:       "BPF_MAP_TYPE_LRU_PERCPU_HASH",
	MapTypeLPMTrie:             "BPF_MAP_TYPE_LPM_TRIE",
	MapTypeArrayOfMaps:         "BPF_MAP_TYPE_ARRAY_OF_MAPS",
	MapTypeHashOfMaps:          "BPF_MAP_TYPE_HASH_OF_MAPS",
	MapTypeDevMap:              "BPF_MAP_TYPE_DEVMAP",
	MapTypeSockMap:             "BPF_MAP_TYPE_SOCKMAP",
	MapTypeCPUMap:              "BPF_MAP_TYPE_CPUMAP",
	MapTypeXSKMap:              "BPF_MAP_TYPE_XSKMAP",
	MapTypeSockHash:            "BPF_MAP_TYPE_SOCKHASH",
	MapTypeCgroupStorage:       "BPF_MAP_TYPE_CGROUP_STORAGE",
	MapTypeReusePortSockArray:  "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
	MapTypePerCPUCgroupStorage: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
	MapTypeQueue:               "BPF_MAP_TYPE_QUEUE",
	MapTypeStack:               "BPF_MAP_TYPE_STACK",
	MapTypeSKStorage:           "BPF_MAP_TYPE_SK_STORAGE",
	MapTypeDevmapHash:          "BPF_MAP_TYPE_DEVMAP_HASH",
	MapTypeStructOps:           "BPF_MAP_TYPE_STRUCT_OPS",
	MapTypeRingbuf:             "BPF_MAP_TYPE_RINGBUF",
	MapTypeInodeStorage:        "BPF_MAP_TYPE_INODE_STORAGE",
	MapTypeTaskStorage:         "BPF_MAP_TYPE_TASK_STORAGE",
	MapTypeBloomFilter:         "BPF_MAP_TYPE_BLOOM_FILTER",
	MapTypeUserRingbuf:         "BPF_MAP_TYPE_USER_RINGBUF",
	MapTypeCgrpStorage:         "BPF_MAP_TYPE_CGRP_STORAGE",
	MapTypeArena:               "BPF_MAP_TYPE_ARENA",
}

func (t MapType) String() string {
	str, ok := mapTypeToString[t]
	if !ok {
		return "UNKNOWN"
	}
	return str
}

func (t MapType) Name() string {
	return t.String()
}

type MapFlag uint32

const (
	MapFlagUpdateAny     MapFlag = iota
	MapFlagUpdateNoExist
	MapFlagUpdateExist
	MapFlagFLock
)

type BPFMapInfo struct {
	Type                  MapType
	ID                    uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	Name                  string
	IfIndex               uint32
	BTFVmlinuxValueTypeID uint32
	NetnsDev              uint64
	NetnsIno              uint64
	BTFID                 uint32
	BTFKeyTypeID          uint32
	BTFValueTypeID        uint32
	MapExtra              uint64
}

func GetMapFDByID(id uint32) (int, error) {
	fd, err := syscall.Open(fmt.Sprintf("/proc/self/fdinfo/%d", id), syscall.O_RDONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("could not find map id %d: %w", id, err)
	}
	return fd, nil
}

func GetMapInfoByFD(fd int) (*BPFMapInfo, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}

	info := &BPFMapInfo{}
	// Implementation would need to use syscall to get map info
	return info, nil
}

func CalcMapValueSize(valueSize int, mapType MapType) (int, error) {
	if valueSize <= 0 {
		return 0, fmt.Errorf("value size must be greater than 0")
	}

	switch mapType {
	case MapTypePerCPUArray,
		MapTypePerCPUHash,
		MapTypeLRUPerCPUHash,
		MapTypePerCPUCgroupStorage:
		elemSize := (uint64(valueSize) + 7) & ^uint64(7) // Round up to 8 bytes
		numCPU := uint64(syscall.NumCPU())
		return int(elemSize * numCPU), nil
	default:
		return valueSize, nil
	}
}
