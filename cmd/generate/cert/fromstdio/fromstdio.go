package fromstdio

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/cmd/generate/shared"
	"cert-ripper-go/pkg/core"
	hostutils "cert-ripper-go/pkg/host"
	"crypto/x509"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"net"
	"path/filepath"
	"time"
)

var (
	Cmd = &cobra.Command{
		Use:     "fromstdio",
		Short:   "Generate a self-signed certificate",
		Long:    ``,
		PreRunE: shared.ValidateCmdFlags,
		Run:     runGenerateFromStdio,
	}

	caPath           string
	caPrivateKeyPath string

	commonName              string
	validFrom               string
	validFor                int64
	country                 *[]string
	state                   *[]string
	city                    *[]string
	street                  *[]string
	postalCode              *[]string
	organization            *[]string
	orgUnit                 *[]string
	oidEmail                string
	emailAddresses          *[]string
	subjectAlternativeHosts *[]string
	localUsage              *bool
	signatureAlg            common.SignatureAlgorithm
	targetPath              string
	certNamePrefix          string
)

func runGenerateFromStdio(cmd *cobra.Command, args []string) {
	if !hostutils.IsValidHostname(commonName) {
		cmd.PrintErrf("Invalid hostname %s", commonName)
		return
	}

	var validFromDateTime time.Time
	if validFrom == "now" {
		validFromDateTime = time.Now()
	} else {
		var parseErr error
		validFromDateTime, parseErr = time.Parse("2006-01-02 15:04:05", validFrom)
		if parseErr != nil {
			cmd.PrintErrf("Invalid date format %s. Error: %s", validFrom, parseErr)
			return
		}
	}

	targetPath = filepath.FromSlash(targetPath)

	caPrivateKey, caPrivateKeyErr := shared.RetrieveOrGeneratePrivateKey(caPrivateKeyPath, targetPath,
		fmt.Sprintf("ca-%s", certNamePrefix), signatureAlg)
	if caPrivateKeyErr != nil {
		cmd.PrintErrf("Failed to load CA private key: %s", caPrivateKeyErr)
		return
	}

	var ca *x509.Certificate
	if caPath != "" {
		var caErr error
		ca, caErr = core.DecodeCACertificate(caPath)
		if caErr != nil {
			cmd.PrintErrf("Failed to read and decode CA from path \"%s\" Error: %s", caPath, caErr)
			return
		}
	} else {
		caInput := core.CaInput{
			NotBefore:      validFromDateTime,
			ValidFor:       time.Duration(validFor) * time.Hour * 24,
			Country:        country,
			State:          state,
			City:           city,
			Street:         street,
			PostalCode:     postalCode,
			Organization:   organization,
			OrgUnit:        orgUnit,
			EmailAddresses: emailAddresses,
			PrivateKey:     caPrivateKey,
		}

		var certErr error
		ca, certErr = core.CreateCertificateAuthority(caInput)
		if certErr != nil {
			cmd.PrintErrf("Failed to create CA certificate. Error: %s", certErr)
			return
		}

		newCACertPath := shared.ComputeCertificatePath(targetPath, fmt.Sprintf("ca-%s", certNamePrefix))
		if saveErr := core.SaveCertificate(newCACertPath, ca, "pem"); saveErr != nil {
			cmd.PrintErrf("Failed to save CA certificate. Error: %s", saveErr)
			return
		}
	}

	privateKey, keyErr := core.GeneratePrivateKey(common.SignatureAlgTox509[signatureAlg])
	if keyErr != nil {
		cmd.PrintErrf("Failed to generate private key. Error: %s", keyErr)
		return
	}

	keyPath := shared.ComputeKeyPath(targetPath, certNamePrefix)
	keyIoError := core.SavePrivateKey(privateKey, keyPath)
	if keyIoError != nil {
		cmd.PrintErrf("Failed to save private key. Error: %s", keyIoError)
		return
	}

	ipAddresses := make([]net.IP, 0)
	if localUsage != nil && *localUsage {
		ipAddresses = append(ipAddresses, net.ParseIP("127.0.0.1"), net.IPv6loopback)
	}

	certInput := core.CertificateInput{
		CommonName:              commonName,
		NotBefore:               validFromDateTime,
		ValidFor:                time.Duration(validFor) * time.Hour * 24,
		Country:                 country,
		State:                   state,
		City:                    city,
		Street:                  street,
		PostalCode:              postalCode,
		Organization:            organization,
		OrgUnit:                 orgUnit,
		OidEmail:                oidEmail,
		EmailAddresses:          emailAddresses,
		SubjectAlternativeHosts: subjectAlternativeHosts,
		PrivateKey:              privateKey,
		CAPrivateKey:            caPrivateKey,
		IPAddresses:             &ipAddresses,
		CA:                      ca,
	}

	certificate, certErr := core.CreateCertificate(certInput)
	if certErr != nil {
		cmd.PrintErrf("Failed to create certificate. Error: %s", certErr)
		return
	}

	certPath := shared.ComputeCertificatePath(targetPath, certNamePrefix)
	if saveErr := core.SaveCertificate(certPath, certificate, "pem"); saveErr != nil {
		cmd.PrintErrf("Failed to save certificate. Error: %s", saveErr)
		return
	}
}

func init() {
	includeGenerateFromStdio(Cmd)
}

func includeGenerateFromStdio(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&commonName, "commonName", "c", "",
		"[Required] Hostname/Common name (example: domain.com).")
	cmd.Flags().StringVarP(&caPath, "caPath", "a", "",
		"[Optional] Path to CA certificate")
	cmd.Flags().StringVarP(&caPrivateKeyPath, "caPrivateKeyPath", "k", "",
		"[Optional] Path to CA certificate's private key. Required if --caPath (-a) is set.")
	cmd.Flags().StringVar(&validFrom, "validFrom", "now",
		"[Optional] Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05 . "+
			"Default: current time (now)")
	cmd.Flags().Int64Var(&validFor, "validFor", 365,
		"[Optional] Duration in days until which the certificates will be valid. "+
			"Default: 365 days")
	country = cmd.Flags().StringSlice("country", nil,
		"[Optional] Country code (example: US). It can accept multiple values divided by comma. "+
			"Default: none")
	state = cmd.Flags().StringSlice("state", nil,
		"[Optional] Province/State (example: California). It can accept multiple values divided by comma. "+
			"Default: none")
	city = cmd.Flags().StringSlice("city", nil,
		"[Optional] Locality/City (example: New-York). It can accept multiple values divided by comma. "+
			"Default: none")
	street = cmd.Flags().StringSlice("street", nil,
		"[Optional] Street Address. It can accept multiple values divided by comma. "+
			"Default: none")
	postalCode = cmd.Flags().StringSlice("postalCode", nil,
		"[Optional] Postal Code. It can accept multiple values divided by comma. "+
			"Default: none")
	organization = cmd.Flags().StringSlice("organization", nil,
		"[Optional] Organization (example: Acme). It can accept multiple values divided by comma. "+
			"Default: none")
	orgUnit = cmd.Flags().StringSlice("organizationUnit", nil,
		"[Optional] Organization unit (example: IT). It can accept multiple values divided by comma. "+
			"Default: none")
	cmd.Flags().StringVar(&oidEmail, "oidEmail", "",
		"[Optional] Object Identifier (OID) Email Address. Default: none")
	emailAddresses = cmd.Flags().StringSlice("email", nil,
		"[Optional] Email Addresses. It can accept multiple values divided by comma. Default: none")
	subjectAlternativeHosts = cmd.Flags().StringSlice("subjectAlternativeHost", nil,
		"[Optional] Subject Alternative Hosts. It can accept multiple values divided by comma. "+
			"Default: none")
	localUsage = cmd.Flags().BoolP("localUsage", "l", true,
		"[Optional] Add local IPs to the certificate so it can be used for localhost.")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "[Optional] Signature Algorithm (allowed values: SHA256WithRSA (default if omitted)"+
			", SHA384WithRSA, SHA512WithRSA, SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().Lookup("signatureAlg").NoOptDefVal = "SHA256WithRSA"
	cmd.Flags().StringVar(&targetPath, "targetPath", ".",
		"[Optional] Target path for the certificate/key pairing to be saved. The target path should be a "+
			"writable directory/folder.")
	cmd.Flags().StringVar(&certNamePrefix, "certNamePrefix", "cert",
		"[Optional] Prefix for the name of the certificate. The certificate will be saved in the folder "+
			"provided with --targetPath. The name of the certificate will be <certNamePrefix>.pem (or other extension "+
			"requested). Additionally, this prefix will be used in the name of the private key and/or the name of the "+
			"ca certificate.")

	if err := cmd.MarkFlagRequired("commonName"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
