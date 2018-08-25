[33mcommit 5b2f08a5240b6c434da5f828824f3036a6c22c64[m[33m ([m[1;36mHEAD -> [m[1;32mmaster[m[33m, [m[1;31morigin/master[m[33m)[m
Author: root <root@localhost.localdomain>
Date:   Sat Aug 25 10:01:09 2018 +0530

    Suprime

[1mdiff --git a/sniff.py b/sniff.py[m
[1mnew file mode 100644[m
[1mindex 0000000..63271e5[m
[1m--- /dev/null[m
[1m+++ b/sniff.py[m
[36m@@ -0,0 +1,15 @@[m
[32m+[m[32mfrom scapy.all import *[m
[32m+[m
[32m+[m[32m# file to sniff[m
[32m+[m[32m'''[m
[32m+[m[32ma = sniff(filter = 'tcp port 80',count = 10)[m
[32m+[m
[32m+[m[32mfor i in range(10):[m
[32m+[m[32m    a[i].show()[m
[32m+[m[32m'''[m[41m    [m
[32m+[m[41m																																																																																	[m
[32m+[m[32mdef sniffer(packet):[m
[32m+[m[32m    print "Source of HTTP is {} and Dst is {}\[m
[32m+[m[32m    {} \n {}".format(packet[IP].src,packet[IP].dst,packet[TCP].dport,str(bytes(packet[TCP].payload)))[m
[32m+[m[41m    [m
[32m+[m[32msniff(filter = 'tcp port 80 ' ,count = 10,prn = sniffer)[m
