package binding

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	metrics "code.cloudfoundry.org/go-metric-registry"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/egress/syslog"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/ingress/applog"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/simplecache"
)

type Poller struct {
	apiClient       client
	pollingInterval time.Duration
	store           Setter

	logger                     *log.Logger
	bindingRefreshErrorCounter metrics.Counter
	lastBindingCount           metrics.Gauge
	invalidDrains              metrics.Gauge
	blacklistedDrains          metrics.Gauge
	appLogStream               applog.AppLogStream
	checker                    IPChecker
	failedHostsCache           *simplecache.SimpleCache[string, bool]
	warn                       bool
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . IPChecker
type IPChecker interface {
	ResolveAddr(host string) (net.IP, error)
	CheckBlacklist(ip net.IP) error
}

type client interface {
	Get(int) (*http.Response, error)
}

type Credentials struct {
	Cert string `json:"cert" yaml:"cert"`
	Key  string `json:"key" yaml:"key"`
	CA   string `json:"ca" yaml:"ca"`
	Apps []App  `json:"apps"`
}

type App struct {
	Hostname string `json:"hostname"`
	AppID    string `json:"app_id"`
}

type Binding struct {
	Url         string        `json:"url" yaml:"url"`
	Credentials []Credentials `json:"credentials" yaml:"credentials"`
}

type AggBinding struct {
	Url  string `yaml:"url"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

type Setter interface {
	Set(bindings []Binding, bindingCount int)
}

func NewPoller(
	ac client,
	pi time.Duration,
	s Setter,
	m Metrics,
	logger *log.Logger,
	logStream applog.AppLogStream,
	checker IPChecker,
	warn bool,
) *Poller {
	opt := metrics.WithMetricLabels(map[string]string{"unit": "total"})

	p := &Poller{
		apiClient:       ac,
		pollingInterval: pi,
		store:           s,
		logger:          logger,
		bindingRefreshErrorCounter: m.NewCounter(
			"binding_refresh_error",
			"Total number of failed requests to the binding provider.",
		),
		lastBindingCount: m.NewGauge(
			"last_binding_refresh_count",
			"Current number of bindings received from binding provider during last refresh.",
		),
		invalidDrains: m.NewGauge(
			"invalid_drains",
			"Count of invalid drains encountered in last binding fetch. Includes blacklisted drains.",
			opt,
		),
		blacklistedDrains: m.NewGauge(
			"blacklisted_drains",
			"Count of blacklisted drains encountered in last binding fetch.",
			opt,
		),
		appLogStream:     logStream,
		checker:          checker,
		failedHostsCache: simplecache.New[string, bool](120 * time.Second),
		warn:             warn,
	}
	p.poll()
	return p
}

func (p *Poller) Poll() {
	for {
		p.poll()
		time.Sleep(p.pollingInterval)
	}
}

func (p *Poller) poll() {
	nextID := 0
	var bindings []Binding
	for {
		resp, err := p.apiClient.Get(nextID)
		if err != nil {
			p.bindingRefreshErrorCounter.Add(1)
			p.logger.Printf("failed to get page %d from internal bindings endpoint: %s", nextID, err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			p.logger.Printf(
				"unexpected response from internal bindings endpoint. status code: %d",
				resp.StatusCode,
			)
			return
		}

		var aResp apiResponse
		err = json.NewDecoder(resp.Body).Decode(&aResp)
		if err != nil {
			p.logger.Printf("failed to decode JSON: %s", err)
			return
		}

		bindings = append(bindings, aResp.Results...)
		nextID = aResp.NextID

		if nextID == 0 {
			break
		}
	}

	bc := &bindingChecker{
		logStream:        &p.appLogStream,
		logger:           p.logger,
		checker:          p.checker,
		failedHostsCache: p.failedHostsCache,
		warn:             p.warn,
	}
	filteredBindings := bc.checkBindings(bindings)
	p.blacklistedDrains.Set(bc.blacklistedDrains)
	p.invalidDrains.Set(bc.invalidDrains)

	bindingCount := CalculateBindingCount(filteredBindings)
	p.lastBindingCount.Set(float64(bindingCount))
	p.store.Set(filteredBindings, bindingCount)
}

// bindingChecker is responsible for validating bindings and keeping track of invalid and blacklisted drain counts. It also sends warning logs when bindings are rejected.
type bindingChecker struct {
	logStream         *applog.AppLogStream
	logger            *log.Logger
	checker           IPChecker
	failedHostsCache  *simplecache.SimpleCache[string, bool]
	warn              bool
	invalidDrains     float64
	blacklistedDrains float64
}

// rejectBinding increments the appropriate drain counters and sends a warning log if necessary
func (bc *bindingChecker) rejectBinding(creds []Credentials, msg string, invalid, blacklisted bool) {
	if invalid {
		bc.invalidDrains++
	}
	if blacklisted {
		bc.blacklistedDrains++
	}
	if bc.warn {
		warnApps(msg, creds, bc.logStream, bc.logger)
	}
}

// checkBindings checks the bindings and returns a filtered list of valid bindings. It also updates the invalid and blacklisted drain counts.
func (bc *bindingChecker) checkBindings(bindings []Binding) []Binding {
	bc.logger.Printf("checking bindings - found %d bindings", len(bindings))
	var filteredBindings []Binding
	for _, b := range bindings {
		if len(b.Credentials) == 0 {
			bc.logger.Printf("no credentials for %s", b.Url)
			continue
		}
		u, err := url.Parse(b.Url)
		if err != nil {
			bc.rejectBinding(b.Credentials, fmt.Sprintf("Cannot parse syslog drain url %s", b.Url), false, false)
			continue
		}

		anonymousUrl := *u
		anonymousUrl.User = nil
		anonymousUrl.RawQuery = ""

		if invalidScheme(u.Scheme) {
			bc.rejectBinding(b.Credentials, fmt.Sprintf("Invalid Scheme for syslog drain url %s", anonymousUrl.String()), false, false)
			continue
		}

		if len(u.Host) == 0 {
			bc.rejectBinding(b.Credentials, fmt.Sprintf("No hostname found in syslog drain url %s", anonymousUrl.String()), false, false)
			continue
		}

		if invalidLogFilter(u) {
			bc.rejectBinding(b.Credentials, fmt.Sprintf("include-log-source-types and exclude-log-source-types cannot be used at the same time in syslog drain url %s", anonymousUrl.String()), true, false)
			continue
		}

		sourceTypes := getUnknownSourceTypes(u.Query())
		if sourceTypes != nil {
			bc.rejectBinding(b.Credentials, fmt.Sprintf("Unknown source types '%s' in source type filter in syslog drain url %s", strings.Join(sourceTypes, ", "), anonymousUrl.String()), true, false)
			continue
		}

		_, exists := bc.failedHostsCache.Get(u.Host)
		if exists {
			bc.rejectBinding(b.Credentials, fmt.Sprintf("Skipped resolve ip address for syslog drain with url %s due to prior failure", anonymousUrl.String()), true, false)
			continue
		}

		ip, err := bc.checker.ResolveAddr(u.Host)
		if err != nil {
			bc.failedHostsCache.Set(u.Host, true)
			bc.rejectBinding(b.Credentials, fmt.Sprintf("Cannot resolve ip address for syslog drain with url %s", anonymousUrl.String()), true, false)
			continue
		}

		err = bc.checker.CheckBlacklist(ip)
		if err != nil {
			bc.rejectBinding(b.Credentials, fmt.Sprintf("Resolved ip address for syslog drain with url %s is blacklisted", anonymousUrl.String()), true, true)
			continue
		}

		var validCredentials []Credentials
		for _, cred := range b.Credentials {
			if len(cred.Cert) > 0 && len(cred.Key) > 0 {
				_, err := tls.X509KeyPair([]byte(cred.Cert), []byte(cred.Key))
				if err != nil {
					bc.rejectBinding([]Credentials{cred}, fmt.Sprintf("failed to load certificate for %s", anonymousUrl.String()), false, false)
					continue
				}
			}

			if len(cred.CA) > 0 {
				certPool := x509.NewCertPool()
				ok := certPool.AppendCertsFromPEM([]byte(cred.CA))
				if !ok {
					bc.rejectBinding([]Credentials{cred}, fmt.Sprintf("failed to load root CA for %s", anonymousUrl.String()), false, false)
					continue
				}
			}

			validCredentials = append(validCredentials, cred)
		}

		if len(validCredentials) > 0 {
			filteredBindings = append(filteredBindings, Binding{
				Url:         b.Url,
				Credentials: validCredentials,
			})
		}
	}
	return filteredBindings
}

func warnApps(msg string, credentials []Credentials, logStream *applog.AppLogStream, logger *log.Logger) {
	for _, cred := range credentials {
		sendAppLogMessage(msg, cred.Apps, logStream, logger)
	}
}

func sendAppLogMessage(msg string, apps []App, logStream *applog.AppLogStream, logger *log.Logger) {
	for _, app := range apps {
		appId := app.AppID
		if appId == "" {
			continue
		}
		logStream.Emit(msg, appId)
		logger.Printf("%s for app %s", msg, appId)
	}
}

var allowedSchemes = []string{"syslog", "syslog-tls", "https", "https-batch"}

func invalidScheme(scheme string) bool {
	for _, s := range allowedSchemes {
		if s == scheme {
			return false
		}
	}

	return true
}

// invalidLogFilter checks if both include-log-source-types and exclude-log-source-types
func invalidLogFilter(u *url.URL) bool {
	includeSourceTypes := u.Query().Get("include-log-source-types")
	excludeSourceTypes := u.Query().Get("exclude-log-source-types")
	if excludeSourceTypes != "" && includeSourceTypes != "" {
		return true
	}
	return false
}

// assumes only one of include-log-source-types or exclude-log-source-types is set
func getUnknownSourceTypes(u url.Values) []string {
	var sourceTypeList string
	includeSourceTypes := u.Get("include-log-source-types")
	excludeSourceTypes := u.Get("exclude-log-source-types")

	if includeSourceTypes != "" {
		sourceTypeList = includeSourceTypes
	} else if excludeSourceTypes != "" {
		sourceTypeList = excludeSourceTypes
	} else {
		return nil
	}

	_, unknownTypes := syslog.ParseSourceTypeList(sourceTypeList)
	return unknownTypes
}

func CalculateBindingCount(bindings []Binding) int {
	apps := make(map[string]bool)
	for _, b := range bindings {
		for _, c := range b.Credentials {
			for _, a := range c.Apps {
				apps[a.AppID] = true
			}
		}
	}
	return len(apps)
}

type apiResponse struct {
	Results []Binding
	NextID  int `json:"next_id"`
}
