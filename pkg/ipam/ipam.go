package ipam

import (
	"errors"
	"github.com/alauda/kube-ovn/pkg/util"
	"k8s.io/klog"
	"net"
	"sync"
)

var (
	OutOfRangeError  = errors.New("AddressOutOfRange")
	ConflictError    = errors.New("AddressConflict")
	NoAvailableError = errors.New("NoAvailableAddress")
	InvalidCIDRError = errors.New("CIDRInvalid")
)

type IPAM struct {
	rw sync.RWMutex
	Subnets map[string]*Subnet
}

func NewIPAM() *IPAM {
	return &IPAM{
		rw:      sync.RWMutex{},
		Subnets: map[string]*Subnet{},
	}
}

func (ipam *IPAM) GetRandomAddress(podName string, subnetName string) (string, error) {
	ipam.rw.RLock()
	defer ipam.rw.RUnlock()
	if subnet, ok := ipam.Subnets[subnetName]; !ok {
		return "", NoAvailableError
	} else {
		ip, err := subnet.GetRandomAddress(podName)
		return string(ip), err
	}
}

func (ipam *IPAM) GetStaticAddress(podName string, ip IP, subnetName string) error {
	ipam.rw.RLock()
	defer ipam.rw.RUnlock()
	if subnet, ok := ipam.Subnets[subnetName]; !ok {
		return NoAvailableError
	} else {
		return subnet.GetStaticAddress(podName, ip, false)
	}
}

func (ipam *IPAM) ReleaseAddressByPod(podName string, subnetName string) {
	ipam.rw.RLock()
	defer ipam.rw.RUnlock()
	subnet, ok := ipam.Subnets[subnetName]
	if !ok {
		return
	}

	subnet.ReleaseAddress(podName)
	return
}

func (ipam *IPAM) AddOrUpdateSubnet(name, cidrStr string, excludeIps []string) error {
	ipam.rw.Lock()
	defer ipam.rw.Unlock()

	_, _, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return InvalidCIDRError
	}

	if subnet, ok := ipam.Subnets[name]; ok {
		subnet.ReservedIPList = convertExcludeIps(excludeIps)
		firstIP, _ := util.FirstSubnetIP(cidrStr)
		lastIP, _ := util.LastSubnetIP(cidrStr)
		subnet.FreeIPList = IPRangeList{&IPRange{Start: IP(firstIP), End: IP(lastIP)}}
		subnet.joinFreeWithReserve()
		for podName, ip := range subnet.PodToIP {
			if err := subnet.GetStaticAddress(podName, ip, true); err!= nil {
				klog.Errorf("%s address not in subnet %s new cidr %s", podName, name, cidrStr)
			}
		}
		return nil
	}

	subnet, err := NewSubnet(name, cidrStr, excludeIps)
	if err != nil {
		return err
	}
	ipam.Subnets[name] = subnet
	return nil
}
