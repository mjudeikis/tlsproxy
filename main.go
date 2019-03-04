package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	kerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/openshift/openshift-azure/pkg/util/log"
)

var (
	// Regular expression used to validate RFC1035 hostnames*/
	hostnameRegex = regexp.MustCompile(`^[[:alnum:]][[:alnum:]\-]{0,61}[[:alnum:]]|[[:alpha:]]$`)
)

var (
	logLevel    = flag.String("loglevel", "Info", "Valid values are Debug, Info, Warning, Error")
	listen      = flag.String("listen", "", "IP/port to listen on")
	insecure    = flag.Bool("insecure", false, "don't validate CA certificate")
	ca          = flag.String("ca", "", "file containing CA certificate(s) for the rewrite hostname")
	cert        = flag.String("cert", "", "file containing client certificate for the rewrite hostname")
	key         = flag.String("key", "", "file containing client key for the rewrite hostname")
	reencrypt   = flag.Bool("reencrypt", false, "re-encrypt traffic with other certificate")
	servingkey  = flag.String("servingkey", "", "file containing serving key for re-encryption")
	servingcert = flag.String("servingcert", "", "file containing serving certificate for re-encryption")
	whitelist   = flag.String("whitelist", "", "URL whitelist regular expression")
	hostname    = flag.String("hostname", "", "Hostname value to rewrite. Example: https://hostname.to.rewrite/")
	configFile  = flag.String("config", "", "config file for tlsProxy. Flags takes priority over config file")
	gitCommit   = "unknown"
)

type config struct {
	// config file field config
	LogLevel    string `json:"loglevel,omitempty"`
	Listen      string `json:"listen,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`
	Ca          string `json:"ca,omitempty"`
	Cert        string `json:"cert,omitempty"`
	Key         string `json:"key,omitempty"`
	Reencrypt   bool   `json:"reencrypt,omitempty"`
	ServingCert string `json:"servingcert,omitempty"`
	ServingKey  string `json:"servingkey,omitempty"`
	Whitelist   string `json:"whitelist,omitempty"`
	Hostname    string `json:"hostname,omitempty"`

	// transformed fields
	username        string
	password        string
	log             *logrus.Entry
	cli             *http.Client
	redirectURL     *url.URL
	whitelistRegexp *regexp.Regexp
}

type envConfig struct {
	// env var config
	Username string `envconfig:"USERNAME"`
	Password string `envconfig:"PASSWORD"`
}

func (c *config) validate() []error {
	var errs []error
	// check variables
	if *hostname != "" && !hostnameRegex.MatchString(*hostname) {
		return append(errs, errors.New("hostname is not a valid hostname"))
	}
	if c.Ca == "" {
		return append(errs, errors.New("cacert must be provided"))
	}
	if c.Cert == "" {
		return append(errs, errors.New("cert must be provided"))
	}
	if c.Key == "" {
		return append(errs, errors.New("key must be provided"))
	}
	if c.Reencrypt {
		if c.ServingKey == "" {
			return append(errs, errors.New("servingkey must be provided for re-encrypt"))
		}
		if c.ServingCert == "" {
			return append(errs, errors.New("servingcert must be provided for re-encrypt"))
		}
	}
	if c.password == "" && c.username != "" ||
		c.password != "" && c.username == "" {
		return append(errs, errors.New("USERNAME and PASSWORD variables must be provided"))
	}

	// check files exist
	if _, err := os.Stat(c.Ca); os.IsNotExist(err) {
		return append(errs, errors.New(fmt.Sprintf("file %s does not exist", c.Ca)))
	}
	if _, err := os.Stat(c.Cert); os.IsNotExist(err) {
		return append(errs, errors.New(fmt.Sprintf("file %s does not exist", c.Cert)))
	}
	if _, err := os.Stat(c.Key); os.IsNotExist(err) {
		return append(errs, errors.New(fmt.Sprintf("file %s does not exist", c.Key)))
	}
	if c.Reencrypt {
		if _, err := os.Stat(c.ServingKey); os.IsNotExist(err) {
			return append(errs, errors.New(fmt.Sprintf("file %s does not exist", c.ServingKey)))
		}
		if _, err := os.Stat(c.ServingCert); os.IsNotExist(err) {
			return append(errs, errors.New(fmt.Sprintf("file %s does not exist", c.ServingCert)))
		}
	}

	return errs
}

func (c *config) Init(path string) error {
	var err error

	// Resolve env to config structure
	ec := envConfig{}
	if err := envconfig.Process("", &ec); err != nil {
		return err
	}

	// resolve config file
	if path != "" {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return err
		}
	}

	// flags takes priority over config file
	setStringField(*logLevel, &c.LogLevel)
	setStringField(*listen, &c.Listen)
	setStringField(*ca, &c.Ca)
	setStringField(*cert, &c.Cert)
	setStringField(*key, &c.Key)
	setStringField(*servingcert, &c.ServingCert)
	setStringField(*servingkey, &c.ServingKey)
	setStringField(*whitelist, &c.Whitelist)
	setStringField(*hostname, &c.Hostname)
	setStringField(ec.Password, &c.password)
	setStringField(ec.Username, &c.username)

	setBoolField(*insecure, &c.Insecure)
	setBoolField(*reencrypt, &c.Reencrypt)

	// set logger
	logrus.SetLevel(log.SanitizeLogLevel(c.LogLevel))
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	c.log = logrus.NewEntry(logrus.StandardLogger())

	// validate flags
	if errs := c.validate(); len(errs) > 0 {
		return errors.Wrap(kerrors.NewAggregate(errs), "cannot validate flags")
	}

	// sanitize inputs
	c.redirectURL, err = url.Parse(c.Hostname)
	if err != nil {
		return err
	}

	c.whitelistRegexp, err = regexp.Compile(c.Whitelist)
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(c.Ca)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)
	cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return err
	}

	c.cli = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Insecure,
				RootCAs:            pool,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}

	return nil
}

func usage() {
	fmt.Printf("Usage:\n")
	fmt.Printf("\"%s -hostname\" url to rewrite \n\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func (c *config) Run() error {

	whitelist, err := regexp.Compile(*whitelist)
	if err != nil {
		return err
	}

	handlerFunc := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = c.redirectURL.Scheme
		req.URL.Host = c.redirectURL.Host
		req.RequestURI = ""
		req.Host = ""

		if !whitelist.MatchString(req.URL.String()) || req.Method != http.MethodGet {
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		// check authentication
		if c.username != "" {
			if !c.checkAuth(rw, req) {
				http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}

		c.log.Debug(req.URL.String())
		resp, err := c.cli.Do(req)
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
	})

	if c.Reencrypt {
		c.log.Debug("starting in reencrypt mode")
		return http.ListenAndServeTLS(c.Listen, c.ServingCert, c.ServingKey, handlerFunc)
	}
	c.log.Debug("starting in plain text mode")
	return http.ListenAndServe(c.Listen, handlerFunc)
}

func (c *config) checkAuth(rw http.ResponseWriter, req *http.Request) bool {
	s := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return false
	}

	return pair[0] == c.username && pair[1] == c.password
}

func setStringField(flag string, result *string) {
	if flag != "" {
		*result = flag
	}
}

func setBoolField(flag bool, result *bool) {
	if flag {
		*result = flag
	}
}

func main() {
	flag.Usage = usage
	flag.Parse()

	c := config{}
	err := c.Init(*configFile)
	if err != nil {
		panic(err)
	}

	c.log.Infof("tlsproxy starting at %s, git commit %s", c.Listen, gitCommit)
	if err := c.Run(); err != nil {
		c.log.Fatal(err)
	}
}
