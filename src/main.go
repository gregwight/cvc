package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

const (
	APPNAME = "cvc"
	APPDESC = "SSL Certificate Validity Checker"
	VERSION = "1.0.0"
	VERDATE = "Feb 2023"
)

func main() {
	flags := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Printf(`
%s
%s

Version:
  %s (%s)

Usage:
  %s [options] <fqdn>[:<host>]

Where:
  <fqdn>     is the FQDN of the webside / SSL certificate to query.
  [:<host>]  is the optional IP address of the host at which to query the FQDN.
             if <host> is ommitted the IP will be resolved from the FQDN.

Options:
`, APPDESC, strings.Repeat("-", len(APPDESC)), VERSION, VERDATE, APPNAME)
		flags.PrintDefaults()
		os.Exit(255)
	}

	var help, verbose, version bool
	flags.BoolVar(&help, "h", false, "Display this help.")
	flags.BoolVar(&help, "help", false, "Display this help.")
	flags.BoolVar(&verbose, "v", false, "Enable verbose output.")
	flags.BoolVar(&version, "version", false, "Display program version.")

	var critDays, warnDays uint
	flags.UintVar(&critDays, "c", 30, "Critical threshold for certificate validity in days.")
	flags.UintVar(&warnDays, "w", 60, "Warning threshold for certificate validity in days.")

	flags.Parse(os.Args[1:])

	if version {
		fmt.Printf("%s %s\n", APPNAME, VERSION)
		os.Exit(0)
	}

	if help || len(flags.Args()) != 1 {
		flags.Usage()
	}

	fqdn, addr, err := getFqdnAddr(flags.Arg(0))
	if err != nil {
		flags.Usage()
	}

	conn, err := tls.Dial("tcp", addr+":443", &tls.Config{ServerName: fqdn})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		os.Exit(2)
	}

	cert := conn.ConnectionState().PeerCertificates[0]

	if verbose {
		t, err := template.New("details").Parse(certDetails)
		if err != nil {
			panic(err)
		}
		err = t.Execute(os.Stdout, cert)
		if err != nil {
			panic(err)
		}
	}

	now := time.Now()
	expiry := cert.NotAfter
	remaining := uint(expiry.Sub(now).Hours() / 24)
	switch {
	case remaining <= critDays:
		fmt.Printf("CRITICAL: %d days remaining unitl certificate expiry on %s\n", remaining, expiry.Format(time.RFC850))
		os.Exit(2)
	case remaining <= warnDays:
		fmt.Printf("WARNING: %d days remaining unitl certificate expiry on %s\n", remaining, expiry.Format(time.RFC850))
		os.Exit(1)
	default:
		fmt.Printf("OK: %d days remaining unitl certificate expiry on %s\n", remaining, expiry.Format(time.RFC850))
	}
}

func getFqdnAddr(arg string) (string, string, error) {
	parts := strings.Split(arg, ":")
	switch len(parts) {
	case 1:
		return parts[0], parts[0], nil
	case 2:
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("Invalid FQDN/IP specification provided: %s", arg)
	}
}

var certDetails string = `Server Certificate:
Issuer: {{ .Issuer }}
Subject: {{ .Subject }}
Valid: {{ .NotBefore.Format "Monday, 02-Jan-2006 15:04:05 GMT" }}
Expiry: {{ .NotAfter.Format "Monday, 02-Jan-2006 15:04:05 GMT" }}
{{ with .DNSNames }}Subject Alternative Names:
{{- range . }}
  {{ . }}
{{- end }}
{{ end }}
`
