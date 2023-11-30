module github.com/khulnasoft-lab/libbpfgo/selftest/tracing

go 1.18

require (
	github.com/khulnasoft-lab/libbpfgo v0.4.7-libbpf-1.2.0-b2e29a1
	github.com/khulnasoft-lab/libbpfgo/helpers v0.4.5
)

require golang.org/x/sys v0.7.0 // indirect

replace github.com/khulnasoft-lab/libbpfgo => ../../

replace github.com/khulnasoft-lab/libbpfgo/helpers => ../../helpers
