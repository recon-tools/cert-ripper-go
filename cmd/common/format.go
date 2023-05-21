package common

import "github.com/thediveo/enumflag/v2"

type CertFormat enumflag.Flag

const (
	PEM CertFormat = iota
	CRT
	CER
	TXT
	DER
	P7B
	P7C
)

var CertFormatIds = map[CertFormat][]string{
	PEM: {"pem"},
	CRT: {"crt"},
	CER: {"cer"},
	TXT: {"txt"},
	DER: {"der"},
	P7B: {"p7b"},
	P7C: {"p7c"},
}
