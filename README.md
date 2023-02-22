# SSL Certificate Validity Checker (CVC)
## Overview
`cvc` is a command-line utility that can be used to check the validity of SSL server certificates, and in particular verify the number of days remaining until the certificate expires. 

The tool can check one or more FQDNs in parallel, and supports the reading of targets from a file. It is also supports targeting a specific host for each FQDN query, and can display common certificate properties when used with the `-v/--verbose` flag.

Exit codes are used to indicate the validation result as shown in the table below, which permits simple integration with most IT infrastructure monitoring platforms to provide alerting for certificate expiry deadlines.

## Exit Codes
| Code | Description | Meaning |
| - | - | - |
| 0 | OK | No issues detected with certificate. |
| 1 | WARNING | Certificate is valid, but expires within `warning threshold` days. |
| 2 | CRITICAL | Certificate is valid, but expires within `critical threshold` days. |
| 3 | ERROR | Certificate is not valid or an error occurred trying to fetch the certificate.
| 4 | UNKNOWN | #Shrug |
| 255 | OTHER | Tool exited for a non-certificate related reason, such as file path not found |

## Usage
A simple query can be performed by just providing an FQDN of interest:
```
> cvc example.com
[OK] example.com (93.184.216.34) 356 days remaining unitl expiry on Tuesday, 13-Feb-24 23:59:59 UTC
```
In this mode `cvc` will resolve the supplied FQDN to an IP address using the system resolver.

To target a specific server IP use the `fqdn:host` target syntax:
```
> cvc example.com:93.184.216.34
[OK] example.com (93.184.216.34) 356 days remaining unitl expiry on Tuesday, 13-Feb-24 23:59:59 UTC
```
It is also possible to use an FQDN for the host, which may be useful in a virtual hosting environment:
```
> cvc example.com:github.com
[ERROR] example.com (140.82.114.4) x509: certificate is valid for github.com, www.github.com, not example.com
```

Multiple target specifications can be provided in a single command:
```
> cvc example.com github.com
[OK] example.com (93.184.216.34) 356 days remaining unitl expiry on Tuesday, 13-Feb-24 23:59:59 UTC
[OK] github.com (140.82.114.3) 386 days remaining unitl expiry on Thursday, 14-Mar-24 23:59:59 UTC
```
In this case the `Exit Code` will be the highest code recorded from all the separate validations.

Multiple targets can also be read from a newline separated text file in `-b/--batch` mode:

Given the file `targets.txt`:
```
example.com
github.com:140.82.114.3
```
Batch mode yields:
```
> cvc -b targets.txt
[OK] example.com (93.184.216.34) 356 days remaining unitl expiry on Tuesday, 13-Feb-24 23:59:59 UTC
[OK] github.com (140.82.114.3) 386 days remaining unitl expiry on Thursday, 14-Mar-24 23:59:59 UTC
```

To specify custom warning and/or critical thresholds for  the expiration deadline use the `-w/--warning`  and/or `-c/--critical` flags:
```
> cvc -c 365 example.com
[CRITICAL] example.com (93.184.216.34) 356 days remaining unitl expiry on Tuesday, 13-Feb-24 23:59:59 UTC

>  cvc -w 365 -b targets.txt
[WARNING] example.com (93.184.216.34) 356 days remaining unitl expiry on Tuesday, 13-Feb-24 23:59:59 UTC
[OK] github.com (140.82.114.3) 386 days remaining unitl expiry on Thursday, 14-Mar-24 23:59:59 UTC

```

To display details of the received certificate use the `-v/--verbose` flag:
```
> cvc -v example.com

> Serial: 16115816404043435608139631424403370993
> Issuer:
>  CN=DigiCert TLS RSA SHA256 2020 CA1
>  O=DigiCert Inc
>  C=US
> Subject:
>  CN=www.example.org
>  O=Internet Corporation for Assigned Names and Numbers
>  L=Los Angeles
>  ST=California
>  C=US
> SubjectAltNames:
>  www.example.org
>  example.net
>  example.edu
>  example.com
>  example.org
>  www.example.com
>  www.example.edu
>  www.example.net
> NotBefore: Friday, 13-Jan-2023 00:00:00 GMT
> NotAfter: Tuesday, 13-Feb-2024 23:59:59 GMT

[OK] example.com (93.184.216.34) 356 days remaining unitl expiry on Tuesday, 13-Feb-24 23:59:59 UTC
```
