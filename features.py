#!/usr/bin/env python
# coding: utf-8


import whois # pip3 install python-whois
import tldextract
from pprint import pprint 
import socket
from collections import OrderedDict
import dns.resolver # pip3 install dnspython


def get_domain(subdomain):
    e = tldextract.extract(subdomain)
    return f'{e.domain}.{e.suffix}'


def get_ns(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = resolver.lifetime = 20.0
    resolver.nameservers = ['8.8.8.8'] # resolve using Google DNS
    try:
        for record in resolver.query(domain, 'NS'):
            record = str(record)
            yield record

    except (dns.resolver.DNSException):
        return False


class URLFeatures:
    def __init__(self, url):
        self.url = url
        self.domain = get_domain(url)
        self.whois = whois.whois(self.domain)
    
    @property
    def creation_date(self):
        return self.whois.creation_date.strftime("%m/%d/%Y, %H:%M:%S")
    
    @property
    def expiration_date(self):
        return self.whois.expiration_date.strftime("%m/%d/%Y, %H:%M:%S")
    
    @property
    def whois_nameservers(self):
        # This will grab the nameservers present 
        # in the WHOIS database, which may not be accurate
        # and sometimes non-existent.
        return self.whois.name_servers

    @property
    def actual_nameservers(self):
        # This will attempt to resolve the nameservers at present
        # using Google's public resolver - will be accurate
        return list(get_ns(self.domain))
    
    @property
    def emails(self):
        return self.whois.emails
    
    @property
    def name(self):
        return self.whois.registrar
    
    @property
    def country_tld(self):
        return tldextract.extract(self.domain).suffix
    
    @property
    def country_name(self):
        raise NotImplementedError
        
    @property
    def hosted_from(self):
        return socket.gethostbyname(self.domain)
    
    def to_dict(self):
        return OrderedDict({
            'domain': obj.domain,
            'creation_date': obj.creation_date,
            'hosted_from': obj.hosted_from,
            'expiration_date': obj.expiration_date,
            'whois_nameservers': obj.whois_nameservers,
            'actual_nameservers': obj.actual_nameservers,
            'emails': obj.emails,
            'name': obj.name
        })


url = 'http://sis.smu.edu.sg/sis-research-overview'

obj = URLFeatures(url)

pprint(obj.to_dict())
