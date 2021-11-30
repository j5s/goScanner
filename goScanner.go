package main

import (
	"fmt"
	"github.com/workcha/goScanner/pkg/Common"
	"github.com/workcha/goScanner/pkg/TXPortMap/GPortScan"
	"github.com/workcha/goScanner/pkg/TXPortMap/Ghttp"
	Gnbtscan "github.com/workcha/goScanner/pkg/TXPortMap/GnbtScan"
)

func main() {
	Gnbtscan.NbtScanTest()
	Ghttp.GetHttpTitleTest()
	result := GPortScan.Scanner("10.5.84.141", 4444)
	print(fmt.Sprintf("%s->%s->%s", result.Target, result.Banner, result.Server))
	ips, _ := Common.CidrParse("10.5.84.141/24")
	ports := Common.GetTop1000Ports()
	result1 := GPortScan.ScanPortsServer(ips, ports, 1000)
	print(len(result1))
}
