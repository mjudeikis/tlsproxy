package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

var (
	listen    = flag.String("listen", ":8080", "IP/port to listen on")
	insecure  = flag.Bool("insecure", false, "don't validate CA certificate")
	cacert    = flag.String("cacert", "", "file containing CA certificate(s)")
	cert      = flag.String("cert", "", "file containing client certificate")
	key       = flag.String("key", "", "file containing client key")
	whitelist = flag.String("whitelist", "", "URL whitelist regular expression")
)

func run() error {
	redirect, err := url.Parse(flag.Arg(0))
	if err != nil {
		return err
	}

	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: *insecure,
	}

	if *cacert != "" {
		b, err := ioutil.ReadFile(*cacert)
		if err != nil {
			return err
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(b)

		tlsClientConfig.RootCAs = pool
	}

	if *cert != "" && *key != "" {
		cert, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			return err
		}
		tlsClientConfig.Certificates = []tls.Certificate{cert}
	}

	cli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
	}

	whitelist, err := regexp.Compile(*whitelist)
	if err != nil {
		return err
	}

	return http.ListenAndServe(*listen, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = redirect.Scheme
		req.URL.Host = redirect.Host
		req.RequestURI = ""
		req.Host = ""

		if !whitelist.MatchString(req.URL.String()) {
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		resp, err := cli.Do(req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		for k, v := range resp.Header {
			rw.Header()[k] = v
		}
		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body)
	}))
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "%s https://hostname.to.rewrite/\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}
