# coding=utf-8
import time
import logging
from threading import Thread
from dns.utils import save, load

from dnslib import DNSRecord, QTYPE


class Recursion:
    def __init__(self, name):
        self.name = name
        self.NSA = None
        self.NS = None
        self.A = None
        self.AAAA = None
        self.PTR = None
        self.off = False

    def __hash__(self):
        return hash(self.name)

    def add_recursion(self, data):
        if data.q.qtype == QTYPE.A:
            self.A = list(map(lambda x: x.rdata, data.rr))
            self.NSA = list(map(lambda x: (x.rname, x.rdata), data.ar))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.AAAA:
            self.AAAA = list(map(lambda x: x.rdata, data.rr))
            self.NSA = list(map(lambda x: (x.rname, x.rdata), data.ar))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.PTR:
            self.PTR = data.auth[0].rdata
        elif data.q.qtype == QTYPE.NS:
            self.NS = list(map(lambda x: x.rdata, data.rr))
            self.NSA = list(map(lambda x: (x.rname, x.rdata), data.ar))
        else:
            pass
        Thread(target=Recursion.remove_recursion, args=(self, data.q.qtype,
                                                        20)).start()

    @staticmethod
    def remove_recursion(self, qtype, ttl):
        time.sleep(ttl)
        if qtype == QTYPE.A:
            self.A = None
            self.NSA = None
            self.NS = None
        elif qtype == QTYPE.AAAA:
            self.AAAA = None
            self.NSA = None
            self.NS = None
        elif qtype == QTYPE.PTR:
            self.PTR = None
        elif qtype == QTYPE.NS:
            self.NS = None
            self.NSA = None
        else:
            pass
        save()
        load()
