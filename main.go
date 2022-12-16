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
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	GroupNameKey = "GROUP_NAME"
)

var (
	logger logr.Logger
)

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

	logger = klogr.New().WithName("cert-manager-webhook-hosttech")
	logger.Info("Hello from cert-manager-webhook-hosttech")

	cmd.RunWebhookServer(groupName,
		&customDNSProviderSolver{},
	)

	klog.Flush()
}

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

	logger.Info("Getting zone information from nameserver", "zone", zone)

	var result internal.ZonesResponse
	var errMsg interface{}

	resp, err := c.client.R().
		SetBearerAuthToken(c.token).
		SetHeader("Accept", "application/json").
		SetQueryParam("query", zone).
		SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
		SetError(&errMsg).  // Unmarshal response into struct automatically if status code >= 400.
		EnableDump().       // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
		Get(c.cfg.APIURL + "/api/user/v1/zones")
	if err != nil {
		return nil, err
	} else if errMsg != nil {
		return nil, fmt.Errorf("could not find zone '%s': %v", zone, errMsg)
	} else if len(result.Data) == 0 {
		return nil, fmt.Errorf("could not find zone '%s'", zone)
	}

	_ = resp

	zoneInfo := result.Data[0]

	logger.Info("Got zone information from nameserver", "zone", zoneInfo)

	return &zoneInfo, nil
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

	var requestBody = internal.TXTRecordRequest{
		Type:    "TXT",
		Name:    acmeDomain,
		Text:    c.challengeRequest.Key,
		TTL:     3600,
		Comment: "Hosttech Solver",
	}

	logger.Info("Adding challenge to nameserver", "domain", acmeDomain, "challenge", c.challengeRequest.Key)

	resp, err := c.client.R().
		SetBearerAuthToken(c.token).
		SetHeader("Accept", "application/json").
		SetBody(requestBody).
		SetPathParam("zoneID", strconv.Itoa(zoneInfo.ID)).
		SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
		SetError(&errMsg).  // Unmarshal response into struct automatically if status code >= 400.
		EnableDump().       // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
		Post(c.cfg.APIURL + "/api/user/v1/zones/{zoneID}/records")
	if err != nil {
		return err
	} else if errMsg != nil {
		return fmt.Errorf("could not add zone '%s' with key '%s': %v", acmeDomain, c.challengeRequest.Key, errMsg)
	} else if result.Data.ID == 0 {
		return fmt.Errorf("could not add zone '%s' with key '%s': %v", acmeDomain, c.challengeRequest.Key, errMsg)
	}

	_ = resp

	return nil
}

func (c *customDNSProviderSolver) getRecords(zoneID int) (*internal.TXTRecordsResponse, error) {
	var result internal.TXTRecordsResponse
	var errMsg interface{}

	logger.Info("Getting TXT records of the zone", "zoneID", zoneID)

	resp, err := c.client.R().
		SetBearerAuthToken(c.token).
		SetHeader("Accept", "application/json").
		SetPathParam("zoneID", strconv.Itoa(zoneID)).
		SetQueryParam("type", "TXT").
		SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
		SetError(&errMsg).  // Unmarshal response into struct automatically if status code >= 400.
		EnableDump().       // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
		Get(c.cfg.APIURL + "/api/user/v1/zones/{zoneID}/records")
	if err != nil {
		return nil, err
	}

	_ = resp

	logger.Info("Found the following records", "records", result)

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

			logger.Info("Deleting TXT record on nameserver",
				"zone", zoneInfo.Name,
				"record.Name", record.Name,
				"record.Text", record.Text,
			)

			resp, err := c.client.R().
				SetBearerAuthToken(c.token).
				SetHeader("Accept", "application/json").
				SetPathParams(pathParams).
				SetResult(&result). // Unmarshal response into struct automatically if status code >= 200 and <= 299.
				SetError(&errMsg).  // Unmarshal response into struct automatically if status code >= 400.
				EnableDump().       // Enable dump at request level to help troubleshoot, log content only when an unexpected exception occurs.
				Delete(c.cfg.APIURL + "/api/user/v1/zones/{zoneID}/records/{recordID}")
			if err != nil {
				return err
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
	err := c.init(cr)
	if err != nil {
		logger.Error(err, "presenting the challenge failed")
		return err
	}

	err = c.addRecord()
	if err != nil {
		logger.Error(err, "adding the record failed")
		return err
	}

	return nil
}

func (c *customDNSProviderSolver) init(cr *acmeV1.ChallengeRequest) error {
	var err error

	c.challengeRequest = cr

	c.cfg, err = loadConfig(cr.Config)
	if err != nil {
		return err
	}

	secret, err := c.clientset.CoreV1().Secrets(cr.ResourceNamespace).Get(context.Background(), c.cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		return err
	} else {
		if len(secret.Data) == 0 {
			return fmt.Errorf("could not find secret '%s' in namespace '%s'",
				c.cfg.SecretName, cr.ResourceNamespace)
		}
	}

	c.token = string(secret.Data["token"])

	c.client = req.C().SetTimeout(120*time.Second)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(cr *acmeV1.ChallengeRequest) error {
	err := c.init(cr)
	if err != nil {
		return err
	}

	return c.deleteRecord()
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
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
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
