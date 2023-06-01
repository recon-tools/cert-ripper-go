package cmd

import (
	"cert-ripper-go/cmd/convert"
	"cert-ripper-go/cmd/export"
	"cert-ripper-go/cmd/generate"
	printCmd "cert-ripper-go/cmd/print"
	"cert-ripper-go/cmd/request"
	"cert-ripper-go/cmd/validate"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
)

// Execute - parse CLI arguments and execute command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Println("There was an error while executing cert-ripper!", err)
		os.Exit(1)
	}
}

var (
	appVersion = "development"
	gitCommit  = "commit"
	rootCmd    = &cobra.Command{
		Use:              "cert-ripper",
		Short:            "The simplified x509 certificate tool.",
		Long:             ``,
		Version:          fmt.Sprintf("%s (%s)", appVersion, gitCommit),
		TraverseChildren: true,
	}
)

func init() {
	rootCmd.AddCommand(printCmd.Cmd, export.Cmd, validate.Cmd, request.Cmd, generate.Cmd, convert.Cmd)
}
