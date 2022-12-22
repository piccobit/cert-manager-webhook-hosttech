OS ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)

IMAGE_NAME := "cert-manager-webhook-hosttech"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

$(shell mkdir -p "$(OUT)")
export TEST_ASSET_ETCD=_test/kubebuilder/bin/etcd
export TEST_ASSET_KUBE_APISERVER=_test/kubebuilder/bin/kube-apiserver
export TEST_ASSET_KUBECTL=_test/kubebuilder/bin/kubectl
export KUBEBUILDER_ASSETS=_test/kubebuilder/bin

test:
	go test -v .

clean: clean-kubebuilder

clean-kubebuilder:
	rm -Rf _test/kubebuilder

build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template \
		--name cert-manager-webhook-hosttech \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG) \
		deploy/cert-manager-webhook-hosttech > "$(OUT)/rendered-manifest.yaml"
