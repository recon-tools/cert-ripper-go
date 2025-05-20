package generate

import (
	"cert-ripper-go/cmd/generate/ca"
	"cert-ripper-go/cmd/generate/cert/fromcsr"
	"cert-ripper-go/cmd/generate/cert/fromstdio"
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:              "generate",
		Short:            "Generate a self-signed certificate",
		Long:             ``,
		TraverseChildren: true,
	}
)

func init() {
	Cmd.AddCommand(fromcsr.Cmd)
	Cmd.AddCommand(fromstdio.Cmd)
	Cmd.AddCommand(ca.Cmd)
}
