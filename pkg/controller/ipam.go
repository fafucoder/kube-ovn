package controller

import (
	"errors"
	"github.com/alauda/kube-ovn/pkg/util"
	"math/big"
	"sync"
)

var (
	ConflictError = errors.New("AddressConflict")
	UnavailableError = errors.New("AddressUnavailable")
)

type IPRange struct {
	Start IP
	End IP
}

func (ipr IPRange) IPExist(ip IP) bool {
	return util.Ip2BigInt(string(ipr.Start)).Cmp(util.Ip2BigInt(string(ip))) <= 0 &&
		util.Ip2BigInt(string(ip)).Cmp(util.Ip2BigInt(string(ipr.End))) <= 0
}

type IPRangeList []*IPRange

func (iprl IPRangeList) IPExist(ip IP) bool {
	for _, ipr := range iprl {
		if ipr.IPExist(ip) {
			return true
		}
	}
	return false
}

type subnetName string
type podName string
type IP string

type IPAM struct {
	mutex sync.Mutex
	FreeIPList map[subnetName]IPRangeList
	ReserveIPList map[subnetName]IPRangeList
	PodToUsedIP map[podName]IP
	UsedIPToPod map[IP]podName
}

func (ipam *IPAM) getAvailableAddress(subnet subnetName) (IP, error) {
	freeList := ipam.FreeIPList[subnet]
	if len(freeList) == 0 {
		return "", UnavailableError
	}
	ipr := freeList[0]
	ip := ipr.Start
	newStart := big.NewInt(0).Add(util.Ip2BigInt(string(ipr.Start)), big.NewInt(1))
	if newStart.Cmp(util.Ip2BigInt(string(ipr.End))) <= 0 {
		ipr.Start = IP(util.BigInt2Ip(newStart))
	} else {
		ipam.FreeIPList[subnet] = ipam.FreeIPList[subnet][1:]
	}
	return ip, nil
}

func splitIPRange(ipr IPRange, ip IP) []IPRange {
	if ip == ipr.Start && ip == ipr.End {
		return nil
	}
	if ip == ipr.Start {
		return []IPRange{{Start: IP(util.BigInt2Ip(big.NewInt(0).Add(util.Ip2BigInt(string(ip)), big.NewInt(1)))), End: ipr.End}}
	}
	if ip == ipr.End {
		return []IPRange{{Start: ipr.Start, End: IP(util.BigInt2Ip(big.NewInt(0).Sub(util.Ip2BigInt(string(ip)), big.NewInt(1))))}}
	}

	return []IPRange{
		{Start: IP(util.BigInt2Ip(big.NewInt(0).Add(util.Ip2BigInt(string(ip)), big.NewInt(1)))), End: ipr.End},
		{Start: ipr.Start, End: IP(util.BigInt2Ip(big.NewInt(0).Sub(util.Ip2BigInt(string(ip)), big.NewInt(1))))},
	}
}

func (ipam *IPAM) getStaticAddress(subnet subnetName, ip IP) error {
	freeList := ipam.FreeIPList[subnet]
	for index, ipr := range freeList {
		if ipr.IPExist(ip) {
			splitedRange := splitIPRange(*ipr, ip)
			newList := []*IPRange{}
			for i, ipr := range freeList {
				if i != index {
					newList = append(newList, ipr)
				} else {
					for _, ipr := range splitedRange {
						newList = append(newList, &ipr)
					}
				}
			}
			return nil
		}
	}
	return UnavailableError
}

func (ipam *IPAM) GetDynamicAddress(podName podName, subnet subnetName) (string, error) {
	ipam.mutex.Lock()
	defer ipam.mutex.Unlock()
	if _, ok := ipam.FreeIPList[subnet]; !ok {
		return "", UnavailableError
	}
	ip ,err := ipam.getAvailableAddress(subnet)
	if err != nil {
		return "", err
	}
	ipam.PodToUsedIP[podName] = ip
	ipam.UsedIPToPod[ip] = podName
	return string(ip), nil
}

func (ipam *IPAM) GetStaticAddress(podName podName, ip IP, subnet subnetName) error {
	ipam.mutex.Lock()
	defer ipam.mutex.Unlock()
	if _, ok := ipam.FreeIPList[subnet]; !ok {
		return UnavailableError
	}

	if existPod, ok := ipam.UsedIPToPod[ip]; ok {
		if existPod == podName {
			return nil
		} else {
			return ConflictError
		}
	}

	if err := ipam.getStaticAddress(subnet, ip); err != nil {
		return err
	} else {
		ipam.PodToUsedIP[podName] = ip
		ipam.UsedIPToPod[ip] = podName
	}
	return nil
}
