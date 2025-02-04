from scapy.all import send, IP, TCP

packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
send(packet)
