package request

import (
	"cert-ripper-go/cmd/request/create"
	"cert-ripper-go/cmd/request/decode"
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:              "request",
		Short:            "Create and decode CSRs (Certificate Signing Request)",
		Long:             ``,
		TraverseChildren: true,
	}
)

func init() {
	Cmd.AddCommand(create.Cmd)
	Cmd.AddCommand(decode.Cmd)
}
