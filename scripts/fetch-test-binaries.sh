#!/usr/bin/env bash
KUBE_VERSION=1.24.1

mkdir _test

curl -fsSL "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-${KUBE_VERSION}-$(go env GOOS)-$(go env GOARCH).tar.gz" -o kubebuilder-tools.tar.gz
tar -C _test -xf kubebuilder-tools.tar.gz

rm kubebuilder-tools.tar.gz
