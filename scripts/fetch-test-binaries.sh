#!/usr/bin/env bash
KUBE_VERSION=1.25.0

# https://storage.googleapis.com/kubebuilder-tools
curl -fsSL "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-${KUBE_VERSION}-$(go env GOOS)-$(go env GOARCH).tar.gz" -o kubebuilder-tools.tar.gz
tar -zvxf kubebuilder-tools.tar.gz

rm kubebuilder-tools.tar.gz
