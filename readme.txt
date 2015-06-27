TCP and UDP ports scan
Support protocols: "SMTP", "POP3", "HTTP", "DNS", "NTP"
Run as sudo because we have raw sockets here
Example: sudo python3 portscan.py -tcp 1 100 -udp 1 100 -t 0.1 -s anytask.urgu.org
Dep: dnslib, requests