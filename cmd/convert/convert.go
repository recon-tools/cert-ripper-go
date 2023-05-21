package convert

import (
	"cert-ripper-go/cmd/common"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

var (
	Cmd = &cobra.Command{
		Use:   "convert",
		Short: "Convert a certificate from one format to another",
		Long:  ``,
		Run:   runConvert,
	}

	sourcePath string
	targetPath string
	certFormat common.CertFormat
)

func runConvert(cmd *cobra.Command, args []string) {
	cmd.Println("Certificate path: " + sourcePath)
}

func init() {
	includePrintFlags(Cmd)
}

func includePrintFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&sourcePath, "path", "p", "",
		"Path to the input certificate file.")
	cmd.Flags().StringVarP(&targetPath, "targetPath", "t", ".",
		"Target path where the output certificate will be saved.")
	cmd.Flags().VarP(
		enumflag.New(&certFormat, "certFormat", common.CertFormatIds, enumflag.EnumCaseInsensitive),
		"format", "f",
		"Exported certificate format; can be 'pem' (default if omitted), 'crt', 'cer', 'der', 'p7b', 'p7c' or 'txt'")

	if err := cmd.MarkFlagRequired("path"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
