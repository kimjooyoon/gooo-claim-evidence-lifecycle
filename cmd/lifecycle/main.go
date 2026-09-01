package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kimjooyoon/gooo-claim-evidence-lifecycle/internal/lifecycle"
)

func main() {
	root := flag.String("root", ".", "input repository root")
	policy := flag.String("policy", ".gooo/claim-evidence-lifecycle.gooo", "Gooo lifecycle contract")
	output := flag.String("output", "output", "caller-owned output directory")
	mode := flag.String("mode", "run", "run, conformance, or integration")
	flag.Parse()

	if err := lifecycle.Run(*root, *policy, *output, *mode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
