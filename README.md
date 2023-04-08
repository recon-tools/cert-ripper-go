# cert-ripper-go

Fetch certificate chain for a hostname or URL.

## Example of Usage

```bash
cert-ripper stackoverflow.com
```

Expected output:

```bash
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