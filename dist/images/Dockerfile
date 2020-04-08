FROM ovs-base:1.1

COPY *.sh /kube-ovn/
COPY 01-kube-ovn.conflist /kube-ovn/01-kube-ovn.conflist

WORKDIR /kube-ovn

COPY kube-ovn /kube-ovn/kube-ovn
COPY kube-ovn-daemon /kube-ovn/kube-ovn-daemon
COPY kube-ovn-pinger /kube-ovn/kube-ovn-pinger
COPY kube-ovn-controller /kube-ovn/kube-ovn-controller
