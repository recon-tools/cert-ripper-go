package convert

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/cert"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"path/filepath"
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
	certificate, decodeErr := cert.DecodeCertificate(sourcePath)
	if decodeErr != nil {
		cmd.PrintErrf("Failed to decode certificate. Error: %s", decodeErr)
		return
	}
	formatStr := common.CertFormatIds[certFormat][0]
	if certFormat == common.DEFAULT {
		formatStr = filepath.Ext(targetPath)
		if len(formatStr) > 0 {
			formatStr = formatStr[1:]
		}
	}

	ioErr := cert.SaveCertificate(targetPath, certificate, formatStr)
	if ioErr != nil {
		cmd.PrintErrf("Failed to save certificate in %s format. Error: %s", certFormat, ioErr)
		return
	}
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
		"Exported certificate format; can be 'pem', 'crt', 'cer', 'der', 'p7b', 'p7c' or 'txt'. "+
			"If omitted, the format will be attempted to be deduced from the targetPath.")

	if err := cmd.MarkFlagRequired("path"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
