package shared

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/core"
	"fmt"
	"github.com/spf13/cobra"
	"path/filepath"
)

func ValidateCmdFlags(cmd *cobra.Command, args []string) error {
	caPath, err := cmd.Flags().GetString("caPath")
	if err != nil {
		return fmt.Errorf("failed to retrieve --caPath flag: %w", err)
	}

	caPrivateKeyPath, err := cmd.Flags().GetString("caPrivateKeyPath")
	if err != nil {
		return fmt.Errorf("failed to retrieve --caPrivateKeyPath flag: %w", err)
	}

	if caPath != "" && caPrivateKeyPath == "" {
		return fmt.Errorf("private key for the CA certificate is missing")
	}

	return nil
}

// RetrieveOrGeneratePrivateKey attempts to read the private key from the location provided by providedKeyPath.
// If the providedKeyPath is empty, it will generate a new private key, and it will save it inside the targetPath
// directory.
func RetrieveOrGeneratePrivateKey(providedKeyPath string, targetPath string, certNamePrefix string,
	signatureAlg common.SignatureAlgorithm) (any, error) {
	if len(providedKeyPath) > 0 {
		return core.ReadKey(providedKeyPath)
	}

	alg, algErr := common.SignatureAlgTox509[signatureAlg]
	if !algErr {
		return nil, fmt.Errorf("unsupported signature algorithm %v", signatureAlg)
	}

	privateKey, keyErr := core.GeneratePrivateKey(alg)
	if keyErr != nil {
		return nil, keyErr
	}

	newKeyPath := ComputeKeyPath(targetPath, certNamePrefix)
	saveErr := core.SavePrivateKey(privateKey, newKeyPath)
	if saveErr != nil {
		return nil, fmt.Errorf("failed to save newly generated private key: %w", saveErr)
	}

	return privateKey, nil
}

// ComputeKeyPath computes the target path where the private key will be saved.
func ComputeKeyPath(targetPath string, certNamePrefix string) string {
	keyName := fmt.Sprintf("%s.key.pem", certNamePrefix)

	keyPath := filepath.Join(targetPath, keyName)

	return keyPath
}

// ComputeCertificatePath Computes the target path where the certificate will be saved.
func ComputeCertificatePath(targetPath string, certNamePrefix string) string {
	certName := fmt.Sprintf("%s.pem", certNamePrefix)

	certPath := filepath.Join(targetPath, certName)

	return certPath
}
