#!/usr/bin/env python
# coding: utf-8


import whois # pip3 install python-whois
import tldextract
import socket
from collections import OrderedDict
import dns.resolver # pip3 install dnspython


def get_domain(subdomain):
    e = tldextract.extract(subdomain)
    return '{}.{}'.format(e.domain, e.suffix)


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
        if (isinstance(self.whois.creation_date, list)):
            return self.whois.creation_date[0].strftime("%m/%d/%Y, %H:%M:%S")
        else:
            return self.whois.creation_date.strftime("%m/%d/%Y, %H:%M:%S")
    
    @property
    def expiration_date(self):
        if (isinstance(self.whois.expiration_date, list)):
            return self.whois.expiration_date[0].strftime("%m/%d/%Y, %H:%M:%S")
        else:
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
            'domain': self.domain,
            'creation_date': self.creation_date,
            'hosted_from': self.hosted_from,
            'expiration_date': self.expiration_date,
            'whois_nameservers': self.whois_nameservers,
            'actual_nameservers': self.actual_nameservers,
            'emails': self.emails,
            'name': self.name,
            'country_tld': self.country_tld
        })



