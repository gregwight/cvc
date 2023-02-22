package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	flag "github.com/spf13/pflag"
)

const (
	APPNAME = "cvc"
	APPDESC = "SSL Certificate Validity Checker"
	VERSION = "1.1.0"
	VERDATE = "Feb 2023"
)

type statusCode int

const (
	OK statusCode = iota
	WARNING
	CRITICAL
	ERROR
	UNKNOWN
)

var statusCodeToString = map[statusCode]string{
	OK:       "OK",
	WARNING:  "WARNING",
	CRITICAL: "CRITICAL",
	ERROR:    "ERROR",
	UNKNOWN:  "UNKNOWN",
}

var certDetails string = `
> Serial: {{ .SerialNumber }}
{{ with (split (.Issuer | printf "%s") ",") }}> Issuer:
{{- range . }}
>  {{ . }}
{{- end }}
{{- end }}
{{ with (split (.Subject | printf "%s") ",") }}> Subject:
{{- range . }}
>  {{ . }}
{{- end }}
{{- end }}
{{ with .DNSNames }}> SubjectAltNames:
{{- range . }}
>  {{ . }}
{{- end }}
{{- end }}
> NotBefore: {{ .NotBefore.Format "Monday, 02-Jan-2006 15:04:05 GMT" }}
> NotAfter: {{ .NotAfter.Format "Monday, 02-Jan-2006 15:04:05 GMT" }}

`

type query struct {
	fqdn       string
	ip         string
	statusCode statusCode
	statusMsg  string
	cert       *x509.Certificate
}

func resolve(fqdn string) (string, error) {
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("Unable to determine IPv4 address for %s", fqdn)
}

func newQuery(arg string) query {
	parts := strings.Split(arg, ":")
	q := query{fqdn: parts[0]}
	switch len(parts) {
	case 1:
		ip, err := resolve(q.fqdn)
		if err != nil {
			q.statusCode = ERROR
			q.statusMsg = fmt.Sprintf("%s", err)
		} else {
			q.ip = ip
		}
	case 2:
		if ip := net.ParseIP(parts[1]); ip != nil {
			q.ip = ip.String()
		} else {
			ip, err := resolve(parts[1])
			if err != nil {
				q.statusCode = ERROR
				q.statusMsg = fmt.Sprintf("%s", err)
			} else {
				q.ip = ip
			}
		}
	default:
		q.statusCode = UNKNOWN
		q.statusMsg = fmt.Sprintf("Invalid FQDN/IP specification provided: %s", arg)
	}
	return q
}

func doQuery(q query, done chan<- query, wg *sync.WaitGroup) {
	defer wg.Done()
	if q.statusCode == OK {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", q.ip+":443", &tls.Config{ServerName: q.fqdn})
		if err != nil {
			q.statusCode = ERROR
			q.statusMsg = fmt.Sprintf("%s", err)
		} else {
			q.cert = conn.ConnectionState().PeerCertificates[0]
		}
	}
	done <- q
}

func main() {
	flags := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Printf(`
%s
%s

Version:
  %s (%s)

Usage:
  %s [options] <fqdn>[:<host>] [<fqdn>:[<host]...]
  %s [options] -b/--batch <filepath>

Where:
  <fqdn>      is the FQDN of the webside / SSL certificate to query.

  [:<host>]   is the optional IP address of the host at which to query the FQDN.
              if <host> is ommitted the IP will be resolved from the FQDN.

  <filepath>  is the path to a file containing newline separated <fqdn>[:<host>] specifications
              for batch checking of SSL certificates.

Options:
`, APPDESC, strings.Repeat("-", len(APPDESC)), VERSION, VERDATE, APPNAME, APPNAME)
		flags.PrintDefaults()
		os.Exit(255)
	}

	var help, verbose, version bool
	flags.BoolVarP(&help, "help", "h", false, "Display this help.")
	flags.BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output.")
	flags.BoolVar(&version, "version", false, "Display program version.")

	var critDays, warnDays uint
	flags.UintVarP(&critDays, "critical", "c", 30, "Critical threshold for certificate validity in days.")
	flags.UintVarP(&warnDays, "warning", "w", 60, "Warning threshold for certificate validity in days.")

	var batch bool
	flags.BoolVarP(&batch, "batch", "b", false, "Batch mode.")

	flags.Parse(os.Args[1:])

	if version {
		fmt.Printf("%s %s\n", APPNAME, VERSION)
		os.Exit(0)
	}

	if help || len(flags.Args()) == 0 {
		flags.Usage()
	}

	targets := make([]string, 0)
	if batch {
		f, err := os.Open(flags.Arg(0))
		if err != nil {
			fmt.Println(err)
			os.Exit(255)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			targets = append(targets, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(err)
			os.Exit(255)
		}
	} else {
		targets = flags.Args()
	}

	done := make(chan query)
	var wg sync.WaitGroup
	for _, target := range targets {
		q := newQuery(target)
		wg.Add(1)
		go doQuery(q, done, &wg)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	var exitCode statusCode
	t := template.Must(template.New("certDetails").Funcs(template.FuncMap{
		"split": func(s, d string) []string {
			return strings.Split(s, d)
		},
	}).Parse(certDetails))
	for q := range done {
		if q.statusCode != OK {
			exitCode = q.statusCode
		} else {
			if verbose {
				err := t.Execute(os.Stdout, q.cert)
				if err != nil {
					panic(err)
				}
			}
			now := time.Now()
			expiry := q.cert.NotAfter
			remaining := uint(expiry.Sub(now).Hours() / 24)
			q.statusMsg = fmt.Sprintf("%d days remaining unitl expiry on %s", remaining, expiry.Format(time.RFC850))
			switch {
			case remaining <= critDays:
				if exitCode < CRITICAL {
					exitCode = CRITICAL
				}
				q.statusCode = CRITICAL
			case remaining <= warnDays:
				if exitCode < WARNING {
					exitCode = WARNING
				}
				q.statusCode = WARNING
			default:
				q.statusCode = OK
			}
		}
		fmt.Printf("[%s] %s (%s) %s\n", statusCodeToString[q.statusCode], q.fqdn, q.ip, q.statusMsg)
	}
	os.Exit(int(exitCode))
}
