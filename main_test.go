package main

import (
	"math/rand"
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
	// "github.com/piccobit/cert-manager-webhook-hosttech/example"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	// fqdn := GetRandomString(20) + "." + zone

	fixture := dns.NewFixture(&customDNSProviderSolver{},
		dns.SetDNSName(zone),
		dns.SetResolvedZone(zone),
		// dns.SetResolvedFQDN(fqdn),
		dns.SetStrict(true),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/hosttech"),
	)
	fixture.RunConformance(t)
}

func GetRandomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
