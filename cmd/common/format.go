package common

import "github.com/thediveo/enumflag/v2"

type CertFormat enumflag.Flag

const (
	DEFAULT CertFormat = iota
	PEM
	CRT
	CER
	TXT
	DER
	P7B
	P7C
)

var CertFormatIds = map[CertFormat][]string{
	DEFAULT: {},
	PEM:     {"pem"},
	CRT:     {"crt"},
	CER:     {"cer"},
	TXT:     {"txt"},
	DER:     {"der"},
	P7B:     {"p7b"},
	P7C:     {"p7c"},
}
