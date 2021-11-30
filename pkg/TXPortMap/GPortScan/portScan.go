package GPortScan

import (
	"fmt"
	"github.com/workcha/goScanner/pkg/TXPortMap/Ghttp"
	"github.com/workcha/goScanner/pkg/TXPortMap/conversion"
	"github.com/workcha/goScanner/pkg/TXPortMap/output"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NBTScanIPMap struct {
	sync.Mutex
	IPS map[string]struct{}
}

type PortScanResult struct {
	Target string
	Banner string
	Server string
}

var (
	Writer     output.Writer
	NBTScanIPs = NBTScanIPMap{IPS: make(map[string]struct{})}
)

func SendIdentificationPacketFunction(data []byte, ip string, port uint64) (int, *output.ResultEvent) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	even := &output.ResultEvent{
		Target: addr,
		Info:   &output.Info{},
	}

	//fmt.Println(addr)
	var dwSvc int = UNKNOWN_PORT
	tout := 3
	conn, err := net.DialTimeout("tcp", addr, time.Duration(tout*1000)*time.Millisecond)
	if err != nil {
		// 端口是closed状态
		//Writer.Request(ip, conversion.ToString(port), "tcp", fmt.Errorf("time out"))
		return SOCKET_CONNECT_FAILED, nil
	}

	defer conn.Close()

	// Write方法是非阻塞的

	if _, err := conn.Write(data); err != nil {
		// 端口是开放的
		Writer.Request(ip, conversion.ToString(port), "tcp", err)
		return dwSvc, even
	}

	// 直接开辟好空间，避免底层数组频繁申请内存
	var fingerprint = make([]byte, 0, 65535)
	var tmp = make([]byte, 256)
	// 存储读取的字节数
	var num int
	var szBan string
	var szSvcName string

	// 这里设置成6秒是因为超时的时候会重新尝试5次，

	readTimeout := 2 * time.Second

	// 设置读取的超时时间为6s
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	for {
		// Read是阻塞的
		n, err := conn.Read(tmp)
		if err != nil {
			// 虽然数据读取错误，但是端口仍然是open的
			// fmt.Println(err)
			if err != io.EOF {
				dwSvc = SOCKET_READ_TIMEOUT
				// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			}
			break
		}

		if n > 0 {
			num += n
			fingerprint = append(fingerprint, tmp[:n]...)
		} else {
			// 虽然没有读取到数据，但是端口仍然是open的
			// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			break
		}
	}
	//Writer.Request(ip, conversion.ToString(port), "tcp", err)
	// 服务识别
	if num > 0 {
		dwSvc = ComparePackets(fingerprint, num, &szBan, &szSvcName)
		//if len(szBan) > 15 {
		//	szBan = szBan[:15]
		//}
		if dwSvc > UNKNOWN_PORT && dwSvc < SOCKET_CONNECT_FAILED {
			//even.WorkingEvent = "found"
			if szSvcName == "ssl/tls" || szSvcName == "http" {
				rst := Ghttp.GetHttpTitle(ip, Ghttp.HTTPorHTTPS, int(port))
				even.WorkingEvent = rst
				cert, err0 := Ghttp.GetCert(ip, int(port))
				if err0 != nil {
					cert = ""
				}
				even.Info.Cert = cert
			} else {
				even.Info.Banner = strings.TrimSpace(szBan)
			}
			even.Info.Service = szSvcName
			even.Time = time.Now()

		}
	}

	return dwSvc, even
}

type Addr struct {
	ip   string
	port int
}

type Engine struct {
	TaskChan    chan Addr
	WorkerCount int
	Wg          *sync.WaitGroup
}

func worker(addr chan Addr, wg *sync.WaitGroup) {
	for ad := range addr {
		r := Scanner(ad.ip, uint64(ad.port))
		if r.Target != "null" {
			println(fmt.Sprintf("%s->%s", r.Target, r.Server))
			result = append(result, r)
		}

		wg.Done()
	}
}

var result []PortScanResult

// 外部端口扫描服务主要调用函数
func ScanPortsServer(ips []string, ports []int, threadCount int) []PortScanResult {
	result = []PortScanResult{}
	addrs := make(chan Addr, threadCount)
	var wg sync.WaitGroup
	for i := 0; i < cap(addrs); i++ {
		go worker(addrs, &wg)
	}
	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1)
			addrs <- Addr{ip: ip, port: port}
		}
	}
	wg.Wait()
	close(addrs)
	return result

}

func testTCPConnection(ip string, port uint64) bool {
	_, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(int(port)),
		time.Second*1)
	if err == nil {
		return true
	}
	return false
}

func Scanner(ip string, port uint64) PortScanResult {
	if testTCPConnection(ip, port) == false {
		return PortScanResult{Target: "null"}
	}
	var dwSvc int
	var iRule = -1
	var bIsIdentification = false
	var resultEvent *output.ResultEvent
	var packet []byte

	// 端口开放状态，发送报文，获取响应
	// 先判断端口是不是优先识别协议端口
	for _, svc := range St_Identification_Port {
		if port == svc.Port {
			bIsIdentification = true
			iRule = svc.Identification_RuleId
			data := st_Identification_Packet[iRule].Packet
			dwSvc, resultEvent = SendIdentificationPacketFunction(data, ip, port)
			break
		}
	}
	if (dwSvc > UNKNOWN_PORT && dwSvc <= SOCKET_CONNECT_FAILED) || dwSvc == SOCKET_READ_TIMEOUT {
		return PortScanResult{Target: resultEvent.Target, Banner: resultEvent.Info.Banner, Server: resultEvent.Info.Service}
	}

	// 发送其他协议查询包
	for i := 0; i < iPacketMask; i++ {
		// 超时2次,不再识别
		if bIsIdentification && iRule == i {
			continue
		}
		if i == 0 {
			// 说明是http，数据需要拼装一下
			var szOption string
			if port == 80 {
				szOption = fmt.Sprintf("%s%s\r\n\r\n", st_Identification_Packet[0].Packet, ip)
			} else {
				szOption = fmt.Sprintf("%s%s:%d\r\n\r\n", st_Identification_Packet[0].Packet, ip, port)
			}
			packet = []byte(szOption)
		} else {
			packet = st_Identification_Packet[i].Packet
		}

		dwSvc, resultEvent = SendIdentificationPacketFunction(packet, ip, port)
		if (dwSvc > UNKNOWN_PORT && dwSvc <= SOCKET_CONNECT_FAILED) || dwSvc == SOCKET_READ_TIMEOUT {
			//Writer.Write(resultEvent)
			if resultEvent != nil {
				return PortScanResult{Target: resultEvent.Target, Banner: resultEvent.Info.Banner, Server: resultEvent.Info.Service}
			}
			return PortScanResult{Target: "null"}
		}
	}
	// 没有识别到服务，也要输出当前开放端口状态
	return PortScanResult{Target: resultEvent.Target, Banner: resultEvent.Info.Banner, Server: resultEvent.Info.Service}
}
