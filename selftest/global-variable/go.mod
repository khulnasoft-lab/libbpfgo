module github.com/khulnasoft-lab/libbpfgo/selftest/global-variable

go 1.21

require github.com/khulnasoft-lab/libbpfgo v0.5.0

require (
	github.com/khulnasoft-lab/libbpfgo/helpers v0.0.0-20240611152355-f6b0954e7163 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

replace github.com/khulnasoft-lab/libbpfgo => ../../
