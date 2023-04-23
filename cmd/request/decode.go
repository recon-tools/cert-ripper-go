package request

import (
	"cert-ripper-go/pkg"
	"fmt"
	"github.com/spf13/cobra"
)

var (
	decodeCmd = &cobra.Command{
		Use:   "decode",
		Short: "Decode and print CSR file to the STDOUT in OpenSSL text format",
		Long:  ``,
		Run:   runDecodeRequest,
	}

	csrPath string
)

func runDecodeRequest(cmd *cobra.Command, args []string) {
	csr, csrErr := pkg.DecodeCSR(csrPath)
	if csrErr != nil {
		fmt.Printf("Failed to decode csr with path %s. Error: %s", csrPath, csrErr)
	}

	ioErr := pkg.PrintCSR(csr)
	if ioErr != nil {
		fmt.Printf("Failed to print csr with path %s. Error: %s", csrPath, csrErr)
	}
}

func init() {
	includeDecodeRequestFlags(Cmd)
}

func includeDecodeRequestFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&csrPath, "path", "",
		"Path for of the CSR file.")
}
