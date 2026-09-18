package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/internal/productwebclient"
)

func main() {
	openAPIPath := flag.String("openapi", "", "Product OpenAPI input")
	outputPath := flag.String("output", "", "generated JavaScript output")
	flag.Parse()
	if *openAPIPath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "openapi and output are required")
		os.Exit(2)
	}
	document, err := os.ReadFile(*openAPIPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	generated, err := productwebclient.Generate(document)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outputPath, generated, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
