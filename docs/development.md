# Development Guide

## How to build Kube-OVN

Kube-OVN is developed by [Go](https://golang.org/) and uses [Go Modules](https://github.com/golang/go/wiki/Modules) to manage dependency.

To minimize image size we use docker experiment buildx features, please enable it through the [reference](https://docs.docker.com/develop/develop-images/build_enhancements/).

```
git clone https://github.com/alauda/kube-ovn.git
cd kube-ovn
make ovs
make release
```

## How to run e2e tests

Kube-OVN uses [KIND](https://kind.sigs.k8s.io/) to setup a local Kubernetes cluster 
and [Ginkgo](https://onsi.github.io/ginkgo/) as the test framework to run the e2e tests.

```
make kind-init
# wait all pod ready

make e2e
```
