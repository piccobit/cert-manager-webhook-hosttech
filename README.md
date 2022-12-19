# ACME webhook for the hosttech DNS API

This solver can be used when you want to use the cert-manager with the [hosttech DNS API](https://api.ns1.hosttech.eu/api/documentation/).

## Installation

### cert-manager

Follow the [instructions](https://cert-manager.io/docs/installation/) using the cert-manager documentation to install it within your cluster.

### Webhook

#### Using the public Helm chart

```bash
helm repo add piccobit https://piccobit.github.io/helm-charts
# Replace the groupName value with your desired domain.
helm install --namespace cert-manager cert-manager-webhook-hosttech piccobit/cert-manager-webhook-hosttech --set groupName=acme.yourdomain.tld
```

#### From a local checkout

```bash
helm install --namespace cert-manager cert-manager-webhook-hosttech .
```
**Note**: The Kubernetes resources used to install the webhook should be deployed within the same namespace as the cert-manager.

To uninstall the webhook run
```bash
helm uninstall --namespace cert-manager cert-manager-webhook-hosttech
```

## Issuer / ClusterIssuer

Create a `ClusterIssuer` or `Issuer` resource as following:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging-v02.api.letsencrypt.org/directory

    # Email address used for ACME registration
    email: mail@example.com # REPLACE THIS WITH YOUR EMAIL!!!

    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-staging

    solvers:
      - dns01:
          webhook:
            # This group needs to be configured when installing the helm package, otherwise the webhook won't have permission to create an ACME challenge for this API group.
            groupName: acme.yourdomain.tld
            solverName: hosttech
            config:
              secretName: hosttech-secret
              apiUrl: https://api.ns1.hosttech.eu/api/user/v1
```

### Credentials
In order to access the hosttech API, the webhook needs an API token.

If you choose another name for the secret than `hosttech-secret`, ensure to modify the value of `secretName` in the `Issuer` or  `ClusterIssuer`.

The secret for the example above will look like this:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: hosttech-secret
type: Opaque
data:
  token: your-base64-encoded-token
```

### Create a certificate

Finally you are now able to create certificates, for example a wildcard certificate:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - "*.example.com"
    - example.com
  issuerRef:
    name: letsencrypt-staging
    kind: ClusterIssuer
  secretName: example-cert
```

## Development

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

First, you need to have hosttech account with access to DNS control panel. You need to create API token and have a registered and verified DNS zone there.
You also must encode your API token into base64 and put the hash into the `testdata/hosttech/hosttech-secret.yml` file.

You can then run the test suite with:

```bash
# First install necessary binaries (this is only required once)
./scripts/fetch-test-binaries.sh
# Then run the tests
TEST_ZONE_NAME=example.com. make verify
```
