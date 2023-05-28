package decode

import (
	"cert-ripper-go/pkg/core"
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:   "decode",
		Short: "Decode and print CSR file to the STDOUT in OpenSSL text format",
		Long:  ``,
		Run:   runDecodeRequest,
	}

	csrPath string
)

func runDecodeRequest(cmd *cobra.Command, args []string) {
	csr, csrErr := core.DecodeCSR(csrPath)
	if csrErr != nil {
		cmd.PrintErrf("Failed to decode csr with path %s. Error: %s", csrPath, csrErr)
		return
	}

	ioErr := core.PrintCSR(csr)
	if ioErr != nil {
		cmd.PrintErrf("Failed to print csr with path %s. Error: %s", csrPath, ioErr)
		return
	}
}

func init() {
	includeDecodeRequestFlags(Cmd)
}

func includeDecodeRequestFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&csrPath, "path", "p", "",
		"[Required] Path for of the CSR file.")

	if err := cmd.MarkFlagRequired("path"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
