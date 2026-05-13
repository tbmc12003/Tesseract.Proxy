package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/equinomics/tesseract-proxy/internal/profile"
)

func main() {
	bundle := flag.String("bundle", "", "")
	sig := flag.String("sig", "", "")
	pub := flag.String("pubkey", "", "")
	flag.Parse()
	res, err := profile.LoadAndVerify(profile.LoadOptions{
		BundlePath: *bundle, SigPath: *sig, PubkeyPath: *pub,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: bundle_version=%s brokers=%d\n", res.Bundle.BundleVersion, len(res.Bundle.Brokers))
}
