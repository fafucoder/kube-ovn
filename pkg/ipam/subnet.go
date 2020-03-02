package ipam

import (
	"github.com/alauda/kube-ovn/pkg/util"
	"net"
	"sync"
)

type Subnet struct {
	Name           string
	mutex          sync.Mutex
	CIDR           *net.IPNet
	FreeIPList     IPRangeList
	ReservedIPList IPRangeList
	PodToIP        map[string]IP
	IPToPod        map[IP]string
}

func NewSubnet(name, cidrStr string, excludeIps []string) (*Subnet, error) {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, InvalidCIDRError
	}

	firstIP, _ := util.FirstSubnetIP(cidrStr)
	lastIP, _ := util.LastSubnetIP(cidrStr)

	subnet := Subnet{
		Name:           name,
		mutex:          sync.Mutex{},
		CIDR:           cidr,
		FreeIPList:     IPRangeList{&IPRange{Start: IP(firstIP), End: IP(lastIP)}},
		ReservedIPList: convertExcludeIps(excludeIps),
		PodToIP: map[string]IP{},
		IPToPod: map[IP]string{},
	}
	subnet.joinFreeWithReserve()
	return &subnet, nil
}

func (subnet *Subnet) GetRandomAddress(podName string) (IP, error) {
	subnet.mutex.Lock()
	defer subnet.mutex.Unlock()
	if ip, ok := subnet.PodToIP[podName]; ok {
		return ip, nil
	}
	if len(subnet.FreeIPList) == 0 {
		return "", NoAvailableError
	}
	freeList := subnet.FreeIPList
	ipr := freeList[0]
	ip := ipr.Start
	newStart := ip.Add(1)
	if newStart.LessThan(ipr.End) || newStart.Equal(ipr.End) {
		ipr.Start = newStart
	} else {
		subnet.FreeIPList = subnet.FreeIPList[1:]
	}
	subnet.PodToIP[podName] = ip
	subnet.IPToPod[ip] = podName
	return ip, nil
}


func (subnet *Subnet) GetStaticAddress(podName string, ip IP, force bool) error {
	subnet.mutex.Lock()
	subnet.mutex.Unlock()
	if !subnet.CIDR.Contains(net.ParseIP(string(ip))) {
		return OutOfRangeError
	}
	if !force {
		if existPod, ok := subnet.IPToPod[ip]; ok {
			if existPod == podName {
				return nil
			} else {
				return ConflictError
			}
		}
	}

	if subnet.ReservedIPList.Contains(ip) {
		subnet.PodToIP[podName] = ip
		subnet.IPToPod[ip] = podName
		return nil
	}

	if split, newFreeList := splitIPRangeList(subnet.FreeIPList, ip); split {
		subnet.FreeIPList = newFreeList
		subnet.PodToIP[podName] = ip
		subnet.IPToPod[ip] = podName
		return nil
	} else {
		return NoAvailableError
	}
}


func (subnet *Subnet) ReleaseAddress(podName string) {
	subnet.mutex.Lock()
	defer subnet.mutex.Unlock()

	if ip, ok := subnet.PodToIP[podName]; ok {
		delete(subnet.PodToIP, podName)
		delete(subnet.IPToPod, ip)
		if !subnet.CIDR.Contains(net.ParseIP(string(ip))) {
			return
		}

		if subnet.ReservedIPList.Contains(ip) {
			return
		}

		if merged, newFreeList := mergeIPRangeList(subnet.FreeIPList, ip); merged {
			subnet.FreeIPList = newFreeList
			return
		}
	}
}

func (subnet *Subnet) joinFreeWithReserve() {
	for _, reserveIpr := range subnet.ReservedIPList {
		newFreeList := IPRangeList{}
		for _, freeIpr := range subnet.FreeIPList {
			if iprl := splitRange(freeIpr, reserveIpr); iprl != nil {
				newFreeList = append(newFreeList, iprl...)
			}
		}
		subnet.FreeIPList = newFreeList
	}
}
