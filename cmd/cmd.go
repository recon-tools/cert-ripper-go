package cmd

import (
	"cert-ripper-go/cmd/export"
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
		Use:     "cert-ripper",
		Short:   "Retrieve the certificate chain for a URL or a hostname.",
		Long:    ``,
		Version: fmt.Sprintf("%s (%s)", appVersion, gitCommit),
	}
)

func init() {
	rootCmd.AddCommand(printCmd.Cmd)
	rootCmd.AddCommand(export.Cmd)
	rootCmd.AddCommand(validate.Cmd)
	rootCmd.AddCommand(request.Cmd)
}
