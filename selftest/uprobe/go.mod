module github.com/khulnasoft-lab/libbpfgo/selftest/uprobe

go 1.21

require (
	github.com/khulnasoft-lab/libbpfgo v0.0.0
	github.com/khulnasoft-lab/libbpfgo/helpers v0.4.5
)

require golang.org/x/sys v0.18.0 // indirect

replace github.com/khulnasoft-lab/libbpfgo => ../../

replace github.com/khulnasoft-lab/libbpfgo/helpers => ../../helpers
