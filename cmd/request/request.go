package request

import (
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:   "request",
		Short: "Create a CSR (certificate signing request)",
		Long:  ``,
	}
)

func init() {
	Cmd.AddCommand(createCmd)
}
