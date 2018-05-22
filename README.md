# arpZebra
ARP+DNS欺骗工具，通达网络安全第三次实验，课堂演示用，严禁非法用途。ARPSpoof，wifi hijack，dns spoof
## Useage:
`./arpZebra -interface wlp5s0 -target "192.168.1.100,192.168.1.1" -gateway "192.168.1.1" -dnscfg ./config.yml`
- -interface 需要监听的网卡，例子是我笔记本电脑的无线网卡  
- -target 需要把哪些主机的流量转到我的电脑，可以指定多个主机，  
"1.2.3.4" 或者 "1.2.3.0/24" 或者 "1.2.3-7.4-12" 或者 "1.2.3.*“或者前面几种的集合 "1.2.3.4, 1.2.3.0/24, ..."  
- -gateway 网关地址，用来ip包转发，把这些主机中到外网的ip包转发给路由器  
- -dnscfg DNS欺骗配置，配置欺骗哪些域名和欺骗的地址，拦截特定的DNS请求包  
