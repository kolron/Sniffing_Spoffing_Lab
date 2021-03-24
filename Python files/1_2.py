from scapy.all import *

a = IP(src = '172.168.0.1', dst = '10.9.0.5')
b = TCP() 
p = a/b 
send(p)

c = IP(src = '10.0.0.27', dst = '10.9.0.5')
d = ICMP(type = "echo-request", code = 0) 
t = c/d
send(t)
print("second packet")

