# ACME webhook for the hosttech DNS API

<!-- vim-markdown-toc GFM -->

* [Installation](#installation)
    * [cert-manager](#cert-manager)
    * [Webhook](#webhook)
        * [Using the public Helm chart](#using-the-public-helm-chart)
        * [From a local checkout](#from-a-local-checkout)
* [Issuer / ClusterIssuer](#issuer--clusterissuer)
    * [Credentials](#credentials)
    * [Create a certificate](#create-a-certificate)
        * [Using a certificate request](#using-a-certificate-request)
        * [Using a Kubernetes Ingress](#using-a-kubernetes-ingress)
* [Development](#development)
    * [Building the webhook Docker image](#building-the-webhook-docker-image)
    * [Running the test suite](#running-the-test-suite)
* [Non-Affiliation & Disclaimer](#non-affiliation--disclaimer)

<!-- vim-markdown-toc -->

This solver can be used when you want to use the **cert-manager** with the [hosttech DNS API](https://api.ns1.hosttech.eu/api/documentation/).

## Installation

### cert-manager

Follow the [instructions](https://cert-manager.io/docs/installation/) using the **cert-manager** documentation to install it within your cluster.

### Webhook

#### Using the public Helm chart

```bash
helm repo add piccobit https://piccobit.github.io/helm-charts
# Replace the groupName value with your desired domain.
helm install --namespace cert-manager cert-manager-webhook-hosttech piccobit/cert-manager-webhook-hosttech --set groupName=acme.yourdomain.tld
```

#### From a local checkout

```bash
# Replace the groupName value with your desired domain.
helm install --namespace cert-manager cert-manager-webhook-hosttech  --set groupName=acme.yourdomain.tld .
```
**Note**: The Kubernetes resources used to install the webhook should be deployed within the same namespace as the **cert-manager**.

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
  namespace: cert-manager
type: Opaque
data:
  token: <your-base64-encoded-token>
```

### Create a certificate

#### Using a certificate request

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

#### Using a Kubernetes Ingress

```yaml
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: www
  annotations:
    kubernetes.io/ingress.class: <nginx|traefik>
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - secretName: wildcard-example-com-tls
    hosts:
    - "*.example.com"
    - "example.com"
  rules:
  - host: www.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: www
            port:
              number: 8080
...
```

## Development

### Building the webhook Docker image

Building of the Docker image with the webhook can be done either manually by using the provided `Makefile` or automatically by using
the GitHub Action workflows.

The following keywords in the commit message are triggering the build of debug, pre-release or release Docker image:

| Keyword        | Action                                            |
| :------------- | :------------------------------------------------ |
| `[RELEASE]`    | Triggers the build of a release Docker image.     |
| `[PRERELEASE]` | Triggers the build of a pre-release Docker image. |
| `[DEBUG]`      | Triggers the build of a debug Docker image.       |

The debug Docker images contains beside the webhook application also the **Delve** debugger. Deploying the Helm chart with the option `debug.enabled=true` will start the **Delve** debugger to listen on the configured port (default: 40000) and waiting for a debug connection from your IDE.

To forward the debug connection to the webhook pod in your Kubernetes cluster use the following command:

```bash
# Using the default debug port 40000
kubectl port-forward -n cert-manager $(kubectl get pods -n cert-manager | grep hosttech | cut -d ' ' -f 1) 40000:40000
```

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with **cert-manager**.

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

## Non-Affiliation & Disclaimer

We are not affiliated, associated, authorized, endorsed by, or in any way officially connected with hostech GmbH, or any of its subsidiaries or its affiliates. 
