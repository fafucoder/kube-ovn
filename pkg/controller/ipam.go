package controller

import (
	"errors"
	"github.com/alauda/kube-ovn/pkg/util"
	"math/big"
	"net"
	"strings"
	"sync"
)

var (
	OutOfRangeError  = errors.New("AddressOutOfRange")
	ConflictError    = errors.New("AddressConflict")
	NoAvailableError = errors.New("NoAvailableAddress")
	InvalidCIDRError = errors.New("CIDRInvalid")
)

type IPRange struct {
	Start IP
	End   IP
}

func (ipr IPRange) IPExist(ip IP) bool {
	return util.Ip2BigInt(string(ipr.Start)).Cmp(util.Ip2BigInt(string(ip))) <= 0 &&
		util.Ip2BigInt(string(ip)).Cmp(util.Ip2BigInt(string(ipr.End))) <= 0
}

type IPRangeList []*IPRange

func (iprl IPRangeList) Contains(ip IP) bool {
	for _, ipr := range iprl {
		if ipr.IPExist(ip) {
			return true
		}
	}
	return false
}

type podName string
type IP string

type Subnet struct {
	Name           string
	mutex          sync.Mutex
	CIDR           *net.IPNet
	FreeIPList     IPRangeList
	ReservedIPList IPRangeList
	PodToIP        map[podName]IP
	IPToPod        map[IP]podName
}

type IPAM struct {
	rw sync.RWMutex
	Subnets map[string]*Subnet
}

func (subnet *Subnet) GetRandomAddress(podName podName) (IP, error) {
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
	newStart := big.NewInt(0).Add(util.Ip2BigInt(string(ipr.Start)), big.NewInt(1))
	if newStart.Cmp(util.Ip2BigInt(string(ipr.End))) <= 0 {
		ipr.Start = IP(util.BigInt2Ip(newStart))
	} else {
		subnet.FreeIPList = subnet.FreeIPList[1:]
	}
	subnet.PodToIP[podName] = ip
	subnet.IPToPod[ip] = podName
	return ip, nil
}

func splitIPRangeList(iprl IPRangeList, ip IP) (bool, IPRangeList) {
	newIPRangeList := []*IPRange{}
	split := false
	ipPlusOne := IP(util.BigInt2Ip(big.NewInt(0).Add(util.Ip2BigInt(string(ip)), big.NewInt(1))))
	ipSubOne := IP(util.BigInt2Ip(big.NewInt(0).Sub(util.Ip2BigInt(string(ip)), big.NewInt(1))))
	for _, ipr := range iprl {
		if split {
			newIPRangeList = append(newIPRangeList, ipr)
			continue
		}

		if ip == ipr.Start && ip != ipr.End {
			newIpr := IPRange{Start: ipPlusOne, End: ipr.End}
			newIPRangeList = append(newIPRangeList, &newIpr)
			split = true
			continue
		}

		if ip == ipr.End && ip != ipr.Start {
			newIpr := IPRange{Start: ipr.Start, End: ipSubOne}
			newIPRangeList = append(newIPRangeList, &newIpr)
			split = true
			continue
		}

		if ip == ipr.Start && ip == ipr.End {
			split = true
			continue
		}

		if ipr.IPExist(ip) {
			newIpr1 := IPRange{Start: ipr.Start, End: ipSubOne}
			newIpr2 := IPRange{Start: ipPlusOne, End: ipr.End}
			newIPRangeList = append(newIPRangeList, &newIpr1, &newIpr2)
			split = true
			continue
		}

		newIPRangeList = append(newIPRangeList, ipr)
	}
	return split, newIPRangeList
}

func mergeIPRangeList(iprl IPRangeList, ip IP) (bool, IPRangeList) {
	newIPRangeList := []*IPRange{}
	merged := false
	ipPlusOne := IP(util.BigInt2Ip(big.NewInt(0).Add(util.Ip2BigInt(string(ip)), big.NewInt(1))))
	ipSubOne := IP(util.BigInt2Ip(big.NewInt(0).Sub(util.Ip2BigInt(string(ip)), big.NewInt(1))))
	if iprl.Contains(ip) {
		return false, nil
	}

	for index, ipr := range iprl {
		if merged {
			newIPRangeList = append(newIPRangeList, ipr)
			continue
		}

		if ipPlusOne == ipr.Start {
			if index == 0 || newIPRangeList[len(newIPRangeList)-1].End != ipSubOne {
				newIpr := IPRange{Start: ip, End: ipr.End}
				newIPRangeList = append(newIPRangeList, &newIpr)
			} else {
				newIPRangeList[len(newIPRangeList)-1].End = ipr.End
			}
			merged = true
			continue
		}

		if index == len(iprl) && ipr.End == ipSubOne {
			newIpr := IPRange{Start: ipr.Start, End: ip}
			newIPRangeList = append(newIPRangeList, &newIpr)
			merged = true
			continue
		}

		if !merged && util.Ip2BigInt(string(ipr.Start)).Cmp(util.Ip2BigInt(string(ip))) > 0 {
			newIpr := IPRange{Start: ip, End: ip}
			newIPRangeList = append(newIPRangeList, &newIpr)
			merged = true
		}
		newIPRangeList = append(newIPRangeList, ipr)
	}
	if !merged {
		newIpr := IPRange{Start: ip, End: ip}
		newIPRangeList = append(newIPRangeList, &newIpr)
	}
	return merged, newIPRangeList
}

func (ipam *IPAM) GetRandomAddress(podName podName, subnetName string) (string, error) {
	ipam.rw.RLock()
	defer ipam.rw.RUnlock()
	if subnet, ok := ipam.Subnets[subnetName]; !ok {
		return "", NoAvailableError
	} else {
		ip, err := subnet.GetRandomAddress(podName)
		return string(ip), err
	}
}

func (subnet *Subnet) GetStaticAddress(podName podName, ip IP) error {
	subnet.mutex.Lock()
	subnet.mutex.Unlock()
	if !subnet.CIDR.Contains(net.ParseIP(string(ip))) {
		return OutOfRangeError
	}
	if existPod, ok := subnet.IPToPod[ip]; ok {
		if existPod == podName {
			return nil
		} else {
			return ConflictError
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

func (ipam *IPAM) GetStaticAddress(podName podName, ip IP, subnetName string) error {
	ipam.rw.RLock()
	defer ipam.rw.RUnlock()
	if subnet, ok := ipam.Subnets[subnetName]; !ok {
		return NoAvailableError
	} else {
		return subnet.GetStaticAddress(podName, ip)
	}
}

func (subnet *Subnet) ReleaseAddress(podName podName) {
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

func (ipam *IPAM) ReleaseAddressByPod(podName podName, subnetName string) {
	ipam.rw.RLock()
	defer ipam.rw.RUnlock()
	subnet, ok := ipam.Subnets[subnetName]
	if !ok {
		return
	}

	subnet.ReleaseAddress(podName)
	return
}

func convertExcludeIps(excludeIps []string) IPRangeList {
	newIPRangeList := make([]*IPRange, 0, len(excludeIps))
	for _, ex := range excludeIps {
		ips := strings.Split(ex, "..")
		if len(ips) == 1 {
			ipr := IPRange{Start: IP(ips[0]), End: IP(ips[0])}
			newIPRangeList = append(newIPRangeList, &ipr)
		} else {
			ipr := IPRange{Start: IP(ips[0]), End: IP(ips[1])}
			newIPRangeList = append(newIPRangeList, &ipr)
		}
	}
	return newIPRangeList
}

func (ipam *IPAM) AddOrUpdateSubnet(name, cidrStr string, excludeIps []string) error {
	ipam.rw.Lock()
	defer ipam.rw.Unlock()

	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return InvalidCIDRError
	}

	if subnet, ok := ipam.Subnets[name]; ok {
		subnet.ReservedIPList = convertExcludeIps(excludeIps)
		if subnet.CIDR == cidr {
			return nil
		} else {
			// re-calculate	free ip
			return nil
		}
	}

	firstIP, _ := util.FirstSubnetIP(cidrStr)
	lastIP, _ := util.LastSubnetIP(cidrStr)

	subnet := Subnet{
		Name:           name,
		mutex:          sync.Mutex{},
		CIDR:           cidr,
		FreeIPList:     IPRangeList{&IPRange{Start: IP(firstIP), End: IP(lastIP)}},
		ReservedIPList: convertExcludeIps(excludeIps),
		PodToIP: map[podName]IP{},
		IPToPod: map[IP]podName{},
	}
	ipam.Subnets[name] = &subnet
	return nil
}

func (a IP) Equal(b IP) bool {
	return a == b
}

func (a IP) LessThan(b IP) bool {
	return util.Ip2BigInt(string(a)).Cmp(util.Ip2BigInt(string(b))) == -1
}

func (a IP) GreaterThan(b IP) bool {
	return util.Ip2BigInt(string(a)).Cmp(util.Ip2BigInt(string(b))) == 1
}

func (a IP) Add(num int64) IP {
	return IP(util.BigInt2Ip(big.NewInt(0).Add(util.Ip2BigInt(string(a)), big.NewInt(num))))
}

func splitRange(a, b *IPRange) IPRangeList {
	if b.End.LessThan(a.Start) || b.Start.GreaterThan(a.End) {
		return IPRangeList{a}
	}

	if (a.Start.Equal(b.Start) || a.Start.GreaterThan(b.Start)) &&
		(a.End.Equal(b.End) || a.End.LessThan(b.End)) {
		return nil
	}

	if (a.Start.Equal(b.Start) || a.Start.GreaterThan(b.Start)) &&
		a.End.GreaterThan(b.End) {
		ipr := IPRange{Start:b.End.Add(1), End: a.End}
		return IPRangeList{&ipr}
	}

	if (a.End.Equal(b.End) || a.End.LessThan(b.End)) &&
		a.Start.LessThan(b.Start) {
		ipr := IPRange{Start:a.Start, End: b.Start.Add(-1)}
		return IPRangeList{&ipr}
	}

	ipr1 := IPRange{Start:a.Start, End: b.Start.Add(-1)}
	ipr2 := IPRange{Start:b.End.Add(1), End: a.End}
	return  IPRangeList{&ipr1, &ipr2}
}

func (subnet *Subnet) joinFreeWithReserve() {
	newFreeList := IPRangeList{}
	for _, reserveIpr := range subnet.ReservedIPList {
		for _, freeIpr := range subnet.FreeIPList {
			if reserveIpr.End.LessThan(freeIpr.Start) {
				break
			}
			if iprl := splitRange(freeIpr, reserveIpr); iprl != nil {
				newFreeList = append(newFreeList, iprl...)
			}
		}
	}
	subnet.FreeIPList = newFreeList
}
