from scapy.all import *

# file to sniff
'''
a = sniff(filter = 'tcp port 80',count = 10)

for i in range(10):
    a[i].show()
'''    
																																																																																	
def sniffer(packet):
    print "Source of HTTP is {} and Dst is {}\
    {} \n {}".format(packet[IP].src,packet[IP].dst,packet[TCP].dport,str(bytes(packet[TCP].payload)))
    
sniff(filter = 'tcp port 80 ' ,count = 10,prn = sniffer)
