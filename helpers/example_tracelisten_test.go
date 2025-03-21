// Deprecated: helpers package is deprecated and will be removed.
// See https://github.com/khulnasoft/tracker/pull/4090
package helpers_test

import (
	"fmt"
	"os"

	"github.com/khulnasoft-lab/libbpfgo/helpers"
)

func ExampleTracePipeListen_usage() {
	go func() {
		err := helpers.TracePipeListen()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		}
	}()
}
