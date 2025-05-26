# cert-ripper-go

`cert-ripper` is a command line tools that can be used to aid working with x509 certificates.

Currently, it offers the following features:

- fetch certificate chain from a host
- save certificates in different formats (PEM, DER, P7B, OpenSSL text)
- generate and decode certificate signing requests (CSR)
- generate self-signed certificates

## Examples of Usage

- Fetch certificate chain:

```bash
cert-ripper print --url=ervinszilagyi.dev
```

- Generate a CSR:

```bash
cert-ripper request create --commonName ervinszilagyi.dev
```

- Decode a CSR:

```bash
cert-ripper request decode --path=csr.pem
```

- Generate a self-signed certificate:

```bash
cert-ripper generate fromstdio --commonName=ervinszilagyi.dev --validFrom="2023-05-09 15:04:05" --validFor=3600 --isCa
```

- Convert a certificate from .p7b format to .pem:

```bash
cert-ripper convert -s certs/pkcs.p7b -t certs/crt.pem
```

For more details about commands ands functionalities, please visit the [documentation](https://github.com/recon-tools/cert-ripper-go/wiki) page.

## Download and Install

### MacOS

Install with homebrew:

```bash
brew tap recon-tools/homebrew-recon-tools
brew install cert-ripper
```

### Debian/Ubuntu

ppa coming, for now download the executable from the [release](https://github.com/recon-tools/cert-ripper-go/releases) page

### Windows/Other

Download the executable from the releases page: https://github.com/recon-tools/cert-ripper-go/releases

## Building

Go 1.22 is required.

### Linux/MacOS

```bash
go build -o target/cert-ripper
```

### Windows

```bash
go build -o target/cert-ripper.exe
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
