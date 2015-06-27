'''
TCP and UDP ports scan
Support protocols: "SMTP", "POP3", "HTTP", "DNS", "NTP"
Run as sudo because we have raw sockets here
Example: sudo python3 portscan.py -tcp 1 100 -udp 1 100 -t 0.1 -s anytask.urgu.org
Dep: dnslib
'''
import socket
import select
import threading
import queue
import time

# Packets headers
from packets_headers import iphdr, udphdr, dnshdr
import ntp_packet
import smtplib
import poplib
import requests

import argparse
import sys

taskQueueTCP = queue.Queue()
taskQueueUDP = queue.Queue()
answerPacketsQueue = queue.Queue()
UDPports = {}
TCPPorts = {}
stopFlag = 0


def host2ip(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except:
        return None


class TCPWorkThread(threading.Thread):

    '''
    Scanning TCP ports with connection method
    '''

    def __init__(self, host, timeout):
        threading.Thread.__init__(self)
        self.host = host
        self.timeout = timeout
        self.known_protocols = ["SMTP", "POP3", "HTTP"]

    def run(self):
        global taskQueueTCP, TCPPorts, stopFlag, answerPacketsQueue
        while 1:
            if stopFlag:
                # print("TCPWorkThread Ended")
                break
            try:
                port_num = taskQueueTCP.get(timeout=1)
                TCPPorts[port_num] = self.connect_by_tcp(
                    self.host, port_num, self.timeout)
                # If port is opened check more precisevly
                if TCPPorts[port_num]["state"] == "opened":
                    answerPacketsQueue.put(
                        {"type": "TCP", "port": port_num, "host": self.host, "timeout": self.timeout})
            except queue.Empty:
                continue

    def connect_by_tcp(self, host, port, timeout):
        global taskQueueTCP
        try:
            print("Scanning tcp port {}".format(port))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            # print(result)
            s.close()
            if (result == 0):
                return {"state": "opened"}
            else:
                return {"state": "closed"}
        # If we get too many open files exception put it one more time in queue
        except socket.error:
            # Too many open files
            taskQueueTCP.put(port)


class UDPWorkThread(threading.Thread):

    '''
    Scaning UDP ports
    We have 3 options:
    1)send UDP - get nothing -> port is filtered|opened
    2)send UDP - get icmp port unreachable -> port is closed
    3)send UDP - get UDP -> port is opened
    '''

    def __init__(self, host, timeout):
        threading.Thread.__init__(self)
        self.host = host
        self.timeout = timeout
        self.answer_type = {1: "ICMP", 2: "UDP", 3: "TCP"}

    def run(self):
        global taskQueueUDP, UDPports, stopFlag
        while 1:
            if stopFlag:
                # print("UDPWorkThread Ended")
                break
            try:
                port_num = taskQueueUDP.get(timeout=1)
                UDPports[port_num] = self.connect_by_udp_dummy_data(
                    self.host, port_num, self.timeout)
                if UDPports[port_num]["state"] == "filtered|opened":
                    known_protocols = ["NTP", "DNS"]
                    for proto in known_protocols:
                        UDPports[port_num] = self.connect_by_udp_known_packets(
                            self.host, port_num, self.timeout, proto)
                        if UDPports[port_num]["state"] == "opened":
                            break
            except queue.Empty:
                continue

    def connect_by_udp_dummy_data(self, host, port, timeout):
        '''
        Try to send dummy data to port
        return port status and recv packet is any
        '''
        global taskQueueUDP, answerPacketsQueue
        try:
            socket_raw = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            socket_raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print("Scanning udp port {}".format(port))
            request_dummy = b"000000000000000000000"
            full_packet = request_dummy
            while full_packet:
                sent = socket_udp.sendto(full_packet, (host, port))
                full_packet = full_packet[sent:]
            ready = select.select([socket_raw, socket_udp], [], [], timeout)
            if not ready[0]:  # Timeout
                # print("Timeout from select")
                return {"state": "filtered|opened", "data": None}
            for s in ready[0]:
                rec_packet, addr = s.recvfrom(1024)
                if self.answer_type[s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)] == 1:
                    return {"state": "closed", "data": rec_packet}
                else:
                    answerPacketsQueue.put(
                        {"type": "UDP", "port": port, "data": rec_packet, "timeout": self.timeout})
                    return {"state": "opened", "data": rec_packet}
        # If we get too many open files exception put it one more time in queue
        except socket.error:
            # Too many open files
            taskQueueUDP.put(port)

    def connect_by_udp_known_packets(self, host, port, timeout, proto):
        '''
        Try to send special packets to host
        Because for ex. (8.8.8.8, 53) answers only on correct dns packets
        return port status and recv packet is any
        '''
        global taskQueueUDP, answerPacketsQueue
        try:
            socket_raw = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            socket_raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if proto == "NTP":
                # print("Scanning udp port {} with {}".format(port, proto))
                ntp_header = ntp_packet.NTPPacket(
                    mode=3, version=3, tx_timestamp=ntp_packet.system_to_ntp_time(time.time()))
                m_ntp_packet = ntp_header.to_data()
                full_packet = m_ntp_packet
            if proto == "DNS":
                # print("Scanning udp port {} with {}".format(port, proto))
                dns_header = dnshdr()
                dns_packet = dns_header.assemble()
                full_packet = dns_packet
            while full_packet:
                sent = socket_udp.sendto(full_packet, (host, port))
                full_packet = full_packet[sent:]
            ready = select.select([socket_raw, socket_udp], [], [], timeout)
            if ready[0] == []:  # Timeout
                # print("Timeout from select")
                return {"state": "filtered|opened", "data": None}
            for s in ready[0]:
                rec_packet, addr = s.recvfrom(1024)
                if self.answer_type[s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)] == 1:
                    return {"state": "closed", "data": rec_packet}
                else:
                    answerPacketsQueue.put(
                        {"type": "UDP", "port": port, "data": rec_packet, "timeout": self.timeout})
                    return {"state": "opened", "data": rec_packet}
        # If we get too many open files exception put it one more time in queue
        except socket.error:
            # Too many open files
            taskQueueUDP.put(port)


class AnswerPacketRecThread(threading.Thread):

    '''
    Recognize application layer protocol in answer packets
    For TCP: Make a connection with spec proto
    For UDP: Try to disassemble recived packet
    '''

    def __init__(self):
        threading.Thread.__init__(self)
        self.known_protocols_udp = ["NTP", "DNS"]
        self.known_protocols_tcp = ["SMTP", "POP3", "HTTP"]

    def run(self):
        global answerPacketsQueue, taskQueueUDP, taskQueueTCP, stopFlag
        global TCPPorts, UDPports
        while 1:
            if stopFlag:
                # print("AnswerPacketRecThread Ended")
                break
            try:
                rec_packet = answerPacketsQueue.get(timeout=1)
                # print(rec_packet)
                if (rec_packet["type"] == "UDP"):
                    for proto in self.known_protocols_udp:
                        if proto == "NTP":
                            try:
                                ntp_header = ntp_packet.NTPPacket()
                                ntp_header.from_data(rec_packet["data"])
                                UDPports[rec_packet["port"]]["name"] = proto
                            except:
                                # It is not a ntp packet
                                # print("It is not a ntp packet")
                                pass
                        if proto == "DNS":
                            try:
                                dns_header = dnshdr()
                                dns_packet = dns_header.disassemble(
                                    rec_packet["data"])
                                UDPports[rec_packet["port"]]["name"] = proto
                            except:
                                # It is not a dns packet
                                # print("It is not a dns packet")
                                pass
                else:
                    for proto in self.known_protocols_tcp:
                        if proto == "SMTP":
                            try:
                                server = smtplib.SMTP(
                                    host=rec_packet["host"], port=rec_packet["port"], timeout=rec_packet["timeout"])
                                TCPPorts[rec_packet["port"]]["name"] = proto
                            except smtplib.SMTPServerDisconnected:
                                # Connected, but we closed it to fast
                                # May be there are smtp server.
                                # In this case we have to increase timeout and
                                # try again
                                pass
                            except socket.timeout:
                                # No smtp server there
                                pass
                            except smtplib.SMTPConnectError:
                                # No smtp server there
                                pass
                        if proto == "POP3":
                            try:
                                server = poplib.POP3(
                                    host=rec_packet["host"], port=rec_packet["port"], timeout=rec_packet["timeout"])
                                TCPPorts[rec_packet["port"]]["name"] = proto
                            except socket.timeout:
                                # No pop3 server there
                                pass
                            except poplib.error_proto:
                                # No pop3 server there
                                pass
                        if proto == "HTTP":
                            try:
                                r = requests.get(
                                    'http://{}:{}'.format(rec_packet["host"], rec_packet["port"]), timeout=rec_packet["timeout"])
                                TCPPorts[rec_packet["port"]]["name"] = proto
                            except:
                                # No http server there
                                pass
            except queue.Empty:
                continue


def parser():
    """
    Parser to work with command line
    """
    parser = argparse.ArgumentParser(
        description='Simple portscan tcp/udp')
    parser.add_argument(
        '--host', '-s', required=True, help="Host to scan")
    parser.add_argument(
        '--tcp_port_range', '-tcp', required=True, type=int, nargs='+', help="Tcp ports range")
    parser.add_argument(
        '--udp_port_range', '-udp', required=True, type=int, nargs='+', help="Udp ports range")
    parser.add_argument(
        '--timeout', '-t', required=True, type=float, help="Timeout")
    namespace = parser.parse_args(sys.argv[1:])
    if not host2ip(namespace.host):
        print("Check youк adress (ex. 'anytask.urgu.org')")
        sys.exit()
    else:
        ip = host2ip(namespace.host)
    if 0 >= namespace.tcp_port_range[0] or namespace.tcp_port_range[1] > 65535 \
            or 0 >= namespace.udp_port_range[0] or namespace.udp_port_range[1] > 65535:
        print("Check ports range", file=sys.stderr)
        sys.exit(0)
    if namespace.timeout < 1:
        print("Your timeout < 1. Some protocols may not be recognized so fast")
    print("Start scanning")
    print("Be patient")
    # print(namespace)
    return {"ip": ip, "tcp": namespace.tcp_port_range, "udp": namespace.udp_port_range, "timeout": namespace.timeout}


def debug():
    # host = "127.0.0.1"
    # host = "188.226.127.2"
    # host = "91.226.136.136"
    host = host2ip("anytask.urgu.org")
    return {"ip": host, "tcp": (52, 53), "udp": (52, 53), "timeout": 1}


def print_queue(m_queue):
    print("Not scaned in {}".format(m_queue))
    while True:
        try:
            elem = m_queue.get(timeout=1)
            print(elem)
        except queue.Empty:
            break
    print("-" * 60)


def main():
    global taskQueueTCP, TCPPorts, taskQueueUDP, UDPports, stopFlag
    args = parser()
    host = args["ip"]
    timeout = args["timeout"]
    tcp_b, tcp_e = args["tcp"][0], args["tcp"][1] + 1
    for tcp_port in range(tcp_b, tcp_e):
        taskQueueTCP.put(tcp_port)

    worker_tcp = TCPWorkThread(host, timeout)
    worker_tcp.start()

    udp_b, udp_e = args["udp"][0], args["udp"][1] + 1
    for udp_port in range(udp_b, udp_e):
        taskQueueUDP.put(udp_port)

    worker_udp = UDPWorkThread(host, timeout)
    worker_udp.start()

    worker_ports_rec = AnswerPacketRecThread()
    worker_ports_rec.start()

    while True:
        try:
            time.sleep(0.5)
            if taskQueueTCP.empty() and taskQueueUDP.empty() and answerPacketsQueue.empty():
                stopFlag = True
                worker_tcp.join()  # block until all tasks are done
                worker_udp.join()
                worker_ports_rec.join()
                break
        # Exit by interruption
        except KeyboardInterrupt:
            print("Exiting...")
            stopFlag = True
            worker_tcp.join()  # block until all tasks are done
            worker_udp.join()
            worker_ports_rec.join()
            print("Exited")
            break

    # Printing results
    print("-" * 60)
    for port in TCPPorts:
        if TCPPorts[port]["state"] == "opened":
            try:
                if TCPPorts[port]["name"]:
                    print("TCP", port, "Opened", TCPPorts[port]["name"])
            except KeyError:
                print("TCP", port, TCPPorts[port]["state"])

    for port in UDPports:
        if UDPports[port]["state"] == "opened":
            try:
                if UDPports[port]["name"]:
                    print("UDP", port, "Opened", UDPports[port]["name"])
            except KeyError:
                print("UDP", port, UDPports[port]["state"])

    # To be shure that all tasks are done
    # print_queue(taskQueueTCP)
    # print_queue(taskQueueUDP)
    # print_queue(answerPacketsQueue)

if __name__ == '__main__':
    main()
