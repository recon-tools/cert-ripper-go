package cmd

import (
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

var rootCmd = &cobra.Command{
	Use:     "cert-ripper",
	Short:   "Retrieve the certificate chain for a URL or a hostname.",
	Long:    ``,
	Version: "0.0.2",
}

func init() {
	rootCmd.AddCommand(printCmd)
}
