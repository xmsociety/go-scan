package network

import (
	"fmt"
	"testing"
)

var scanner = NewScanner()

func TestGetOutBoundIP(t *testing.T) {
	fmt.Sprintf(GetOutBoundIP())
}

func TestScanner_ScanPort(t *testing.T) {
	for _, r := range scanner.ScanPort("", 0, 0) {
		fmt.Println(r.Protocol, r.IPAddress, r.Port, r.Status)
	}
}

func TestScanner_ScanHost(t *testing.T) {
	scanner.ScanHost()
}
