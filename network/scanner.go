package network

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProtocolType string

var m sync.Mutex

const (
	TCP  ProtocolType = "tcp"
	TCP4 ProtocolType = "tcp4"
	TCP6 ProtocolType = "tcp6"
	UDP  ProtocolType = "udp"
	UDP4 ProtocolType = "udp4"
	UDP6 ProtocolType = "udp6"

	PortNum int = 1 << 16
)

type Scanner struct {
	LocalHost string
}

type portScanResult struct {
	Protocol  ProtocolType
	IPAddress string
	Port      int
	Status    bool
}

type hostScanResult struct {
	IPAddress  string
	MacAddress string
	HostName   string
	Platform   string
}

func GetOutBoundIP() (ip string, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Println("Get local ip error!", err.Error())
		return
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	log.Println("Local ip: ", localAddr.String())
	ip = strings.Split(localAddr.String(), ":")[0]
	return
}

func NewScanner() *Scanner {
	localIp, err := GetOutBoundIP()
	if err != nil {
		return nil
	}
	return &Scanner{LocalHost: localIp}
}

func (scanner *Scanner) scanPortAsync(protocol ProtocolType, hostname string, port int, results *[]portScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	result := portScanResult{Protocol: protocol, Port: port, IPAddress: scanner.LocalHost}

	p := strconv.Itoa(port)
	addr := net.JoinHostPort(hostname, p)
	// 继续扫描，如果端口号打开，那么不会返回err
	conn, err := net.DialTimeout(string(protocol), addr, 1*time.Second)
	if err != nil {
		// nothing
	} else {
		defer conn.Close()
		result.Status = true
		m.Lock()
		defer m.Unlock()
		*results = append(*results, result)
	}

}

func (scanner *Scanner) ScanPort(hostname string, portStart, portEnd int) []portScanResult {
	if hostname == "" {
		hostname = scanner.LocalHost
	}
	address := net.ParseIP(hostname)
	if address == nil {
		log.Println("Wrong IP Address Or HostName")
		return nil
	}
	if portStart > portEnd || portStart < 0 || portEnd > 65535 {
		log.Println("Wrong port range!")
		return nil
	}
	if portStart == 0 {
		portStart = 1
	}
	if portEnd == 0 {
		portEnd = PortNum
	}
	var results []portScanResult
	wg := &sync.WaitGroup{}
	protocolList := []ProtocolType{TCP, UDP}
	for port := portStart; port < portEnd; port++ {
		for _, protocol := range protocolList {
			wg.Add(1)
			go scanner.scanPortAsync(protocol, hostname, port, &results, wg)
		}
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

func (scanner *Scanner) scanHostAsync(host string, results *[]hostScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	remoteAddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
	// 拨号
	conn, err := net.DialIP("ip4:icmp", nil, remoteAddr)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
	log.Println(conn)
}

func (scanner *Scanner) ScanHost() {
	// TODO
	ipSlice := strings.Split(scanner.LocalHost, ".")
	ipPrefix := strings.Join(ipSlice[:len(ipSlice)-1], ".")
	results := &[]hostScanResult{}
	wg := &sync.WaitGroup{}
	for i := 1; i < 256; i++ {
		wg.Add(1)
		scanner.scanHostAsync(ipPrefix+"."+strconv.Itoa(i), results, wg)
	}
	wg.Wait()
}

func ping(host string) {
	conn, err := net.Dial("ip:icmp", host)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer conn.Close()
	var msg [512]byte
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4] = 0
	msg[5] = 13
	msg[6] = 0
	msg[7] = 37
	msg[8] = 99
	length := 9
	check := checkSum(msg[0:length])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 0xff)
	for i := 0; i < 2; i++ {
		_, err = conn.Write(msg[0:length])
		if err != nil {
			continue
		}
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 400))
		_, err := conn.Read(msg[0:])
		if err != nil {
			continue
		}
		if msg[20+5] == 13 && msg[20+7] == 37 && msg[20+8] == 99 {
			//host is up
			fmt.Printf("%s open\n", host)
			//openHostList = append(openHostList, host)
			return
		}
	}
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

////tcp探测端口是否开放
//conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Duration(timeout)*time.Millisecond)
////icmp探测主机是否存活
//conn, err := net.Dial("ip:icmp", host)
