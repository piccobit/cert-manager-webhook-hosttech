package main

import (
	"context"
	"encoding/json"
	"fmt"
	acmeV1 "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/go-logr/logr"
	"github.com/imroc/req/v3"
	"github.com/piccobit/cert-manager-webhook-hosttech/internal"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	GroupNameKey = "GROUP_NAME"
)

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manage/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	cfg              *customDNSProviderConfig
	clientset        kubernetes.Clientset
	challengeRequest *acmeV1.ChallengeRequest
	token            string
	client *req.Client
	logger *logr.Logger
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIURL     string `json:"apiURL"`
	SecretName string `json:"secretName"`
}

func main() {
	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.

	klog.InitFlags(nil)

	groupName := os.Getenv(GroupNameKey)
	if len(groupName) == 0 {
		panic(fmt.Errorf("environment variable '%s' with the group name is missing", GroupNameKey))
	}

	cmd.RunWebhookServer(groupName,
		&customDNSProviderSolver{},
	)

	klog.Flush()
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "hosttech"
}

func (c *customDNSProviderSolver) getZone(crZone string) (*internal.Zone, error) {
	zone := strings.TrimSuffix(crZone, ".")

	c.logger.WithName("getZone").Info("Getting zone information from nameserver", "zone", zone)

	var result internal.ZonesResponse
	var errMsg interface{}

	u := c.cfg.APIURL + "/zones"

	c.logger.WithName("getZone").Info("apiURL", "u", u)

	resp, err := c.client.R().
		SetBearerAuthToken(c.token).
		SetHeader("Accept", "application/json").
		SetQueryParam("query", zone).
		SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
		SetError(&errMsg). // Unmarshal response into struct automatically if status code >= 400.
		EnableDump(). // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
		Get(u)
	if err != nil {
		return nil, err
	} else if errMsg != nil {
		return nil, fmt.Errorf("could not find zone '%s': errMsg: '%v'", zone, errMsg)
	} else if len(result.Data) == 0 {
		return nil, fmt.Errorf("could not find zone '%s'", zone)
	}

	_ = resp

	zoneInfo := result.Data[0]

	c.logger.WithName("getZone").Info("Got zone information from nameserver", "zoneInfo", zoneInfo)

	return &zoneInfo, nil
}

func (c *customDNSProviderSolver) getAPIURL(cmd string) (*string, error) {
	baseAPIURL, err := url.Parse(c.cfg.APIURL)
	if err != nil {
		return nil, err
	}

	apiURL := baseAPIURL.JoinPath(cmd)

	u := baseAPIURL.ResolveReference(apiURL).String()

	return &u, nil
}

func (c *customDNSProviderSolver) addRecord() error {
	zoneInfo, err := c.getZone(c.challengeRequest.ResolvedZone)
	if err != nil {
		return err
	}

	var result internal.ZoneResponse
	var errMsg interface{}

	acmeDomain := strings.TrimSuffix(
		c.challengeRequest.ResolvedFQDN,
		"."+c.challengeRequest.ResolvedZone)

	challenge := c.challengeRequest.Key

	var requestBody = internal.TXTRecordRequest{
		Type:    "TXT",
		Name:    acmeDomain,
		Text:    challenge,
		TTL:     3600,
		Comment: "Hosttech Solver",
	}

	c.logger.WithName("addRecord").Info("Adding challenge to nameserver", "acmeDomain", acmeDomain, "challenge", challenge)

	u := c.cfg.APIURL + "/zones/{zoneID}/records"

	c.logger.WithName("addRecord").Info("apiURL", "u", u)

	resp, err := c.client.R().
		SetBearerAuthToken(c.token).
		SetHeader("Accept", "application/json").
		SetBody(requestBody).
		SetPathParam("zoneID", strconv.Itoa(zoneInfo.ID)).
		SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
		SetError(&errMsg).  // Unmarshal response into struct automatically if status code >= 400.
		EnableDump().       // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
		Post(u)
	if err != nil {
		return err
	} else if errMsg != nil {
		return fmt.Errorf("could not add challenge '%s' to nameserver: acmeDomain: '%s', errMsg: '%v'", challenge, acmeDomain, errMsg)
	} else if result.Data.ID == 0 {
		return fmt.Errorf("could not add challenge '%s' to nameserver: acmeDomain: '%s'", challenge, acmeDomain)
	}

	_ = resp

	return nil
}

func (c *customDNSProviderSolver) getRecords(zoneID int) (*internal.TXTRecordsResponse, error) {
	var result internal.TXTRecordsResponse
	var errMsg interface{}

	c.logger.WithName("getRecords").Info("Getting TXT records of the zone", "zoneID", zoneID)

	u := c.cfg.APIURL + "/zones/{zoneID}/records"

	c.logger.WithName("getRecords").Info("apiURL", "u", u)

	resp, err := c.client.R().
		SetBearerAuthToken(c.token).
		SetHeader("Accept", "application/json").
		SetPathParam("zoneID", strconv.Itoa(zoneID)).
		SetQueryParam("type", "TXT").
		SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
		SetError(&errMsg).  // Unmarshal response into struct automatically if status code >= 400.
		EnableDump().       // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
		Get(u)
	if err != nil {
		return nil, err
	} else if errMsg != nil {
		return nil, fmt.Errorf("could not get records for zone with ID '%d': errMsg: '%v'", zoneID, errMsg)
	} else if len(result.Data) == 0 {
		return nil, fmt.Errorf("could not get records for zone with ID '%d'", zoneID)
	}

	_ = resp

	c.logger.WithName("getRecords").Info("Got the following records", "records", result)

	return &result, nil
}

func (c *customDNSProviderSolver) deleteRecord() error {
	zoneInfo, err := c.getZone(c.challengeRequest.ResolvedZone)
	if err != nil {
		return err
	}

	records, err := c.getRecords(zoneInfo.ID)
	if err != nil {
		return err
	}

	acmeDomain := strings.TrimSuffix(
		c.challengeRequest.ResolvedFQDN,
		"."+c.challengeRequest.ResolvedZone)

	for _, record := range records.Data {
		if record.Name == acmeDomain {
			var result internal.ZoneResponse
			var errMsg interface{}

			var pathParams = map[string]string{
				"zoneID":   strconv.Itoa(zoneInfo.ID),
				"recordID": strconv.Itoa(record.ID),
			}

			c.logger.WithName("deleteRecord").Info("Deleting TXT record on nameserver",
				"zoneInfo.Name", zoneInfo.Name,
				"record.Name", record.Name,
				"record.Text", record.Text,
			)

			u := c.cfg.APIURL + "/zones/{zoneID}/records/{recordID}"

			c.logger.WithName("deleteRecord").Info("apiURL", "u", u)

			resp, err := c.client.R().
				SetBearerAuthToken(c.token).
				SetHeader("Accept", "application/json").
				SetPathParams(pathParams).
				SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
				SetError(&errMsg).  // Unmarshal response into struct automatically if status code >= 400.
				EnableDump().       // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
				Delete(u)
			if err != nil {
				return err
			} else if errMsg != nil {
				return fmt.Errorf("could not delete TXT record '%s' from zone '%s'", record.Name, zoneInfo.Name)
			}

			_ = resp
		}
	}

	return nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(cr *acmeV1.ChallengeRequest) error {
	err := c.initialize(cr)
	if err != nil {
		c.logger.WithName("Present").Error(err, "Initialization failed")
		return err
	}

	err = c.addRecord()
	if err != nil {
		c.logger.WithName("Present").Error(err, "Adding the record failed")
		return err
	}

	return nil
}

func (c *customDNSProviderSolver) initialize(cr *acmeV1.ChallengeRequest) error {
	var err error

	c.challengeRequest = cr

	c.cfg, err = loadConfig(cr.Config)
	if err != nil {
		return err
	}

	c.logger.WithName("loadConfig").Info("Config loaded",
		"APIURL", c.cfg.APIURL,
		"SecretName", c.cfg.SecretName,
	)

	secret, err := c.clientset.CoreV1().Secrets(cr.ResourceNamespace).Get(context.Background(), c.cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		return err
	} else {
		if len(secret.Data) == 0 {
			return fmt.Errorf("could not find secret '%s' in namespace '%s'",
				c.cfg.SecretName, cr.ResourceNamespace)
		}
	}

	bToken := secret.Data["token"]

	c.token = string(bToken)
	c.client = req.C().SetTimeout(120*time.Second)

	visToken := c.token[:10] + "..." + c.token[len(c.token)-10:]

	c.logger.WithName("initialize").Info("Secret", "c.token", visToken)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(cr *acmeV1.ChallengeRequest) error {
	err := c.initialize(cr)
	if err != nil {
		c.logger.WithName("Cleanup").Error(err, "Initialization failed")
		return err
	}

	err = c.deleteRecord()
	if err != nil {
		c.logger.WithName("Cleanup").Error(err, "Deleting the record failed")
		return err
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	logger := klogr.New().WithName("cmw-hosttech")

	c.logger = &logger

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		c.logger.WithName("Initialize").Error(err, "Initialization failed")
		return err
	}

	c.clientset = *cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (*customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return &cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	return &cfg, nil
}
