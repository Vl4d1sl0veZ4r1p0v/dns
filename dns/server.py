# coding=utf-8
import time
import dns.recursion as recoursion
import logging

import socket
from dnslib import DNSRecord, QTYPE, dns, AAAA, A, NS

from dns.utils import save, load, cache

PORT = 53
HOST = '127.0.0.1'
HOSTDNS = '8.26.56.26'
Alive = True
flag = False
default_ttl = 20


def send_dns_request(dns_server, p):
    try:
        dns_server.send(p)
        p2, a2 = dns_server.recvfrom(1024)
        logging.INFO('Sent a request to my dns-server')
        return p2
    except Exception as ex:
        logging.ERROR('DNS server not responding')


def start():
    global cache, Alive, flag, default_ttl
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_server:
            server.bind((HOST, PORT))
            server.settimeout(10)
            dns_server.connect((HOSTDNS, PORT))
            dns_server.settimeout(10)
            logging.INFO('Server started')
            while True:
                while Alive:
                    try:
                        client_req, client_addr = server.recvfrom(1024)
                        client_data = DNSRecord.parse(client_req)

                    except Exception as ex:
                        logging.ERROR('There were no requests for 10 seconds')
                        continue
                    flag = True
                    if str(client_data.q.qname) in cache:
                        recourse = cache.get(str(client_data.q.qname))
                        query = client_data.reply()
                        if client_data.q.qtype == QTYPE.A and recourse.A:
                            flag = False
                            for addr in recourse.A:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.A,
                                           ttl=default_ttl,
                                           rdata=A(addr.data)))
                            for ns in recourse.NS:
                                query.add_auth(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for e in recourse.NSA:
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                if len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))
                        elif client_data.q.qtype == QTYPE.AAAA and recourse.AAAA:
                            flag = False
                            for addr in recourse.AAAA:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.AAAA,
                                           ttl=default_ttl,
                                           rdata=AAAA(addr.data)))
                            for ns in recourse.NS:
                                query.add_auth(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for e in recourse.NSA:
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                if len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))
                        elif client_data.q.qtype == QTYPE.PTR and recourse.PTR:
                            flag = False
                            query.add_auth(dns.RR(rname=client_data.q.qname,
                                                  rclass=client_data.q.qclass,
                                                  rtype=QTYPE.SOA,
                                                  ttl=default_ttl,
                                                  rdata=recourse.PTR))
                        elif client_data.q.qtype == QTYPE.NS and recourse.NS:
                            flag = False
                            for ns in recourse.NS:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for e in recourse.NSA:
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                if len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))
                        else:
                            server_packet = send_dns_request(dns_server, client_req)
                            server_data = DNSRecord.parse(
                                server_packet)
                            cache.get(str(client_data.q.qname)).add_recursion(
                                server_data)
                            logging.INFO("Cached")
                            server.sendto(server_packet, client_addr)
                            logging.INFO('Sent a reply')
                            continue
                    if flag:
                        server_packet = send_dns_request(dns_server, client_req)
                        server_data = DNSRecord.parse(server_packet)
                        cache[str(client_data.q.qname)] = recoursion.Recursion(
                            str(client_data.q.qname))
                        cache.get(str(client_data.q.qname)).add_recursion(
                            server_data)
                        server.sendto(server_packet, client_addr)
                        logging.INFO('Sent a reply')
                    else:
                        server.sendto(query.pack(), client_addr)
                save()
                cache = {}
                logging.INFO('I saved the cache')
                logging.INFO('Server is down')
                while not Alive:
                    time.sleep(5)
                    logging.INFO('Server started')
                load()
                logging.INFO('Uploaded save')
