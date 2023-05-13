# cert-ripper-go

Fetch certificate chain for a hostname or URL.

## Example of Usage

```bash
$ cert-ripper -h
Retrieve the certificate chain for a URL or a hostname.

Usage:
  cert-ripper [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  export      Export the certificates from the chain and save them into a folder
  generate    Generate a self-signed certificate
  help        Help about any command
  print       Print the certificates from the chain to the standard output
  request     Create and decode CSRs (Certificate Signing Request)
  validate    Validate the certificate

Flags:
  -h, --help      help for cert-ripper
  -v, --version   version for cert-ripper

Use "cert-ripper [command] --help" for more information about a command.
```

### `print` command:

Displays a certificate on the standard output in OpenSSL format.

Example of usage:

```bash
cert-ripper print --url=stackoverflow.com
```

Expected output:

```
Found 4 certificates in the certificate chain for stackoverflow.com 
===========================
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 304654416220459475292011240363286494111390 (0x37f4c8249f4024f228c33cba3198752e69e)
    Signature Algorithm: SHA256-RSA
        Issuer: C=US,O=Let's Encrypt,CN=R3
        Validity
...
```

### `export` command:

Saves the whole certificate chain in a folder. The certificates from the chain can be saved in different formats.

Example of usage:

- With shorthands:
```bash
cert-ripper export -u ervinszilagyi.dev -p certs -f pem
```

- With long commands
```bash
cert-ripper export --url=ervinszilagyi.dev --path=certs --format=txt
```

### `validate` command:

Validates the server certificate using the following steps:

1. Check the expiration date
2. Check if the certificate is trusted using the trust store from the host machine
3. Check if the certificate is not part of a revocation list

Example of usage:

```bash
cert-ripper validate -u ervinszilagyi.dev
```

### `request` command:

`request` command can be used to work with Certificate Signing Requests (CSR). It has the following subcommands:

```bash
Create and decode CSRs (Certificate Signing Request)

Usage:
  cert-ripper request [command]

Available Commands:
  create      Create a CSR (certificate signing request)
  decode      Decode and print CSR file to the STDOUT in OpenSSL text format
```

- `create` command - used to create a CSR request with a private key

```bash
Create a CSR (certificate signing request)

Usage:
  cert-ripper request create [flags]

Flags:
      --city string                 Locality/City (example: New-York)
      --commonName string           Common name (example: domain.com).
      --country string              Country code (example: US).
      --email string                Email address
  -h, --help                        help for create
      --organization string         Organization (example: Acme)
      --organizationUnit string     Organization unit (example: IT)
      --signatureAlg signatureAlg   Signature Algorithm (allowed values: SHA256WithRSA, SHA384WithRSA, SHA512WithRSA,SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA) (default SHA256WithRSA)
      --state string                Province/State (example: California)
      --targetPath string           Target path for the CSR to be saved. (default ".")

```

Example:

```bash
cert-ripper request create \
--commonName=ervinszilagyi.dev \
--country=RO \
--email=mail@ervinszilagyi.dev \
--oidEmail=mail@oid.com \
--organization="home,ACME" \
--organizationUnit="IT,HR" \
--postalCode=222111 \
--state=Mures \
--city="Tg Mures" \
--street="Gh. Doja" \
--subjectAlternativeHosts="alter.nativ,example.com" \
--targetPath=test.csr
```

- `decode` command - used to decode a CSR and display it in OpenSSL format 

```bash
Decode and print CSR file to the STDOUT in OpenSSL text format

Usage:
  cert-ripper request decode [flags]

Flags:
  -h, --help          help for decode
      --path string   Path for of the CSR file.
```

Example:

```bash
cert-ripper request decode --path="certs/request.csr"
```

### `generate` command - used to generate self-signed certificates

```bash
cert-ripper generate
Generate a self-signed certificate

Usage:
  cert-ripper generate [command]

Available Commands:
  fromcsr     Generate a self-signed certificate from a CSR request
  fromstdio   Generate a self-signed certificate

Flags:
  -h, --help   help for generate
```

With `fromcsr` subcommand we can generate a self-signed certificate using an existing CSR.

```bash
Generate a self-signed certificate from a CSR request

Usage:
  cert-ripper generate fromcsr [flags]

Flags:
      --csrPath string          Path to the CSR in PEM format. (default ".")
  -h, --help                    help for fromcsr
      --privateKeyPath string   Path to the Private Key in PEM format (default ".")
      --targetPath string       Path to save the generated certificate (default ".")
      --validFor int            Duration in days until which the certificates will be valid (default 365)
      --validFrom string        Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05 (default "now")
```

With `fromstdio` subcommand we can generate a self-signed certificate by explicitly passing the necessary arguments.

```bash
Generate a self-signed certificate

Usage:
  cert-ripper generate fromstdio [flags]

Flags:
      --city strings                                Locality/City (example: New-York). It can accept multiple values divided by comma.
      --commonName string                           Hostname/Common name (example: domain.com).
      --country strings                             Country code (example: US). It can accept multiple values divided by comma.
      --email strings                               Email Addresses. It can accept multiple values divided by comma.
  -h, --help                                        help for fromstdio
      --isCa                                        Specify if the currently generated certificate should be its own Certificate Authority
      --oidEmail string                             Object Identifier (OID) Email Address
      --organization strings                        Organization (example: Acme). It can accept multiple values divided by comma.
      --organizationUnit strings                    Organization unit (example: IT). It can accept multiple values divided by comma.
      --postalCode strings                          Postal Code. It can accept multiple values divided by comma.
      --signatureAlg signatureAlg[=SHA256WithRSA]   Signature Algorithm (allowed values: SHA256WithRSA (default if omitted), SHA384WithRSA, SHA512WithRSA, SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA) (default SHA256WithRSA)
      --state strings                               Province/State (example: California). It can accept multiple values divided by comma.
      --street strings                              Street Address. It can accept multiple values divided by comma.
      --subjectAlternativeHost strings              Subject Alternative Hosts. It can accept multiple values divided by comma.
      --targetPath string                           Target path for the CSR to be saved. (default "./cert.pem")
      --validFor int                                Duration in days until which the certificates will be valid (default 365)
      --validFrom string                            Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05 (default "now")
```

Example:

```bash
cert-ripper generate fromstdio \
--commonName=example.com \
--validFrom="2023-05-09 15:04:05" \
--validFor=3600 \
--isCa
```

Example with all the possible fields:

```bash
cert-ripper generate fromstdio \
--commonName=ervinszilagyi.dev \
--country=RO \
--email=mail@ervinszilagyi.dev \
--oidEmail=mail@oid.com \
--organization="home,ACME" \
--organizationUnit="IT,HR" \
--postalCode=222111 \
--state=Mures \
--city="Tg Mures" \
--street="Gh. Doja" \
--subjectAlternativeHost="alter.nativ,example.com" \
--targetPath=test.cert \
--validFrom="2023-05-09 15:04:05" \
--validFor=3600 \
--isCa
```

## Download and Install

### MacOS

Install with homebrew:

```bash
brew tap recon-tools/homebrew-recon-tools
brew install cert-ripper-go
```

### Debian/Ubuntu

ppa coming, for now download the executable from the [release](https://github.com/recon-tools/cert-ripper-go/releases) page

### Windows/Other

Download the executable from the releases page: https://github.com/recon-tools/cert-ripper-go/releases

## Building

Go 1.19 is required.

```bash
cd cert-ripper-go
go build -o target/cert-ripper
```

### Build with ldflags

```bash
go build -ldflags "-X 'cert-ripper-go/cmd.appVersion=0.0.1'" -o target/cert-ripper
```

## Tests

Running tests:

```bash
go test ./...
```