package shared

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/core"
	"fmt"
	"path"
)

// RetrieveOrGeneratePrivateKey attempts to read the private key from the location provided by providedKeyPath.
// If the providedKeyPath is empty, it will generate a new private key, and it will save it inside the targetPath
// directory.
func RetrieveOrGeneratePrivateKey(providedKeyPath string, targetPath string, certNamePrefix string,
	signatureAlg common.SignatureAlgorithm, isCA bool) (any, error) {
	if len(providedKeyPath) > 0 {
		return core.ReadKey(providedKeyPath)
	}
	privateKey, keyErr := core.GeneratePrivateKey(common.SignatureAlgTox509[signatureAlg])
	if keyErr != nil {
		return nil, keyErr
	}

	newKeyPath := ComputeKeyPath(targetPath, certNamePrefix, isCA)
	saveErr := core.SavePrivateKey(privateKey, newKeyPath)
	if saveErr != nil {
		return nil, saveErr
	}

	return privateKey, nil
}

// ComputeKeyPath computes the target path where the private key will be saved.
func ComputeKeyPath(targetPath string, certNamePrefix string, isCA bool) string {
	caPrefix := ""
	if isCA {
		caPrefix = fmt.Sprintf("ca-%s", caPrefix)
	}
	keyName := fmt.Sprintf("%s%s.key.pem", caPrefix, certNamePrefix)

	keyPath := path.Join(targetPath, keyName)

	return keyPath
}

// ComputeCertificatePath Computes the target path where the certificate will be saved.
func ComputeCertificatePath(targetPath string, certNamePrefix string, isCA bool) string {
	caPrefix := ""
	if isCA {
		caPrefix = fmt.Sprintf("ca-%s", caPrefix)
	}
	certName := fmt.Sprintf("%s%s.pem", caPrefix, certNamePrefix)

	certPath := path.Join(targetPath, certName)

	return certPath
}
