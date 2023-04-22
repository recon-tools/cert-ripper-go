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
  help        Help about any command
  print       Print the certificates from the chain to the standard output
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
go build .
```

### Build with ldflags

```bash
go build -ldflags "-X 'cert-ripper-go/cmd.appVersion=0.0.1'" .
```