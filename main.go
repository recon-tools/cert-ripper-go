package main

import (
	"github.com/spf13/cobra"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Parse CLI arguments
var rootCmd = &cobra.Command{
	Use:   "cert-ripper",
	Short: "Get the certificate chain for a URL.",
	Long:  "Get the certificate chain for a URL.",
	Args:  cobra.ExactArgs(1),
	Run:   run,
}

// Handle CLI arguments and trigger the business logic.
func run(cmd *cobra.Command, args []string) {
	rawUrl := args[0]
	var u *url.URL
	if isValidHostname(rawUrl) {
		u = &url.URL{
			Host: rawUrl,
		}
	} else {
		var parseErr error
		u, parseErr = url.ParseRequestURI(rawUrl)
		if parseErr != nil {
			log.Println("Error parsing URL", parseErr)
		}
	}

	certs, err := getCertificateChain(u)
	if err != nil {
		log.Println("Error fetching certificate chain:", err)
	}
	printCertificates(u.Host, certs)
}

// Check if the input string is a valid hostname.
func isValidHostname(host string) bool {
	host = strings.Trim(host, " ")
	re, _ := regexp.Compile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	return re.MatchString(host)
}

// Main entry point
func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Println("There was an error while executing cert-ripper!", err)
		os.Exit(1)
	}
}
