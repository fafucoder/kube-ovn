package util

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"

	kubeovnv1 "github.com/alauda/kube-ovn/pkg/apis/kubeovn/v1"
)

// GenerateMac generates mac address.
func GenerateMac() string {
	prefix := "00:00:00"
	newRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	mac := fmt.Sprintf("%s:%02X:%02X:%02X", prefix, newRand.Intn(255), newRand.Intn(255), newRand.Intn(255))
	return mac
}

func Ip2BigInt(ipStr string) *big.Int {
	ipBigInt := big.NewInt(0)
	if CheckProtocol(ipStr) == kubeovnv1.ProtocolIPv4 {
		ipBigInt.SetBytes(net.ParseIP(ipStr).To4())
	} else {
		ipBigInt.SetBytes(net.ParseIP(ipStr).To16())
	}
	return ipBigInt
}

func BigInt2Ip(ipInt *big.Int) string {
	ip := net.IP(ipInt.Bytes())
	return ip.String()
}

func FirstSubnetIP(subnet string) (string, error) {
	_, cidr, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid cidr", subnet)
	}
	ipInt := Ip2BigInt(cidr.IP.String())
	return BigInt2Ip(ipInt.Add(ipInt, big.NewInt(1))), nil
}

func LastSubnetIP(subnet string) (string, error) {
	_, cidr, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid cidr", subnet)
	}
	var length uint
	if CheckProtocol(subnet) == kubeovnv1.ProtocolIPv4 {
		length = 32
	} else {
		length = 128
	}
	maskLength, _ := cidr.Mask.Size()
	ipInt := Ip2BigInt(cidr.IP.String())
	size := big.NewInt(0).Lsh(big.NewInt(1), length-uint(maskLength))
	size = big.NewInt(0).Sub(size, big.NewInt(2))
	return BigInt2Ip(ipInt.Add(ipInt, size)), nil
}

func CIDRConflict(a, b string) bool {
	aIp, aIpNet, aErr := net.ParseCIDR(a)
	bIp, bIpNet, bErr := net.ParseCIDR(b)
	if aErr != nil || bErr != nil {
		return false
	}
	return aIpNet.Contains(bIp) || bIpNet.Contains(aIp)
}

func CheckProtocol(address string) string {
	address = strings.Split(address, "/")[0]
	ip := net.ParseIP(address)
	if ip.To4() != nil {
		return kubeovnv1.ProtocolIPv4
	}
	return kubeovnv1.ProtocolIPv6
}

func AddressCount(network *net.IPNet) uint64 {
	prefixLen, bits := network.Mask.Size()
	return 1 << (uint64(bits) - uint64(prefixLen))
}

func GetHostInterface() map[string]string {
	var IfName map[string]string
	routes, err := netlink.RouteList(nil, syscall.AF_INET)
	if err != nil {
		return IfName
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
			if route.LinkIndex <= 0 {
				continue
			}

			iface, err := net.InterfaceByIndex(route.LinkIndex)
			if err != nil {
				continue
			}

			addr, err := iface.Addrs()
			if err != nil && len(addr) > 0 {
				IfName[iface.Name] = strings.Split(addr[0].String(), "/")[0]
			} else {
				IfName[iface.Name] = "false"
			}
		}
	}

	return IfName
}
