package request

import (
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:   "request",
		Short: "Create and decode CSRs (Certificate Signing Request)",
		Long:  ``,
	}
)

func init() {
	Cmd.AddCommand(createCmd)
	Cmd.AddCommand(decodeCmd)
}
