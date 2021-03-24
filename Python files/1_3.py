from scapy.all import *
dest = "8.8.8.8"
i = 1  #ttl
flag = True
route = []
while flag and i <= 64:# limiting hops to 64
    pkt = IP(dst=dest, ttl=i) / ICMP(type = 8, code = 0) #construct a packet
    reply = sr(pkt, timeout = 2) #send packet and get the reply
    if reply[0][0][1].type == 0: #if reply.type is echo reply
        flag = False #finish the while 
        print ("Reached destination", reply[0][0][1].src) #print destination just to see we actually got it right
    else:
        print ("%d hops away: " % i , reply[0][0][1].src)
        i += 1 #increase ttl by 1
        route.append(reply[0][0][1].src) #add the checkpoint to the route list

print(route)

 
