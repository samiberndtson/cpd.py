#!/usr/bin/env python
#-*- coding:utf-8 -*-

import sys
import http.client
import urllib.request
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urlsplit
import random
import json
import re
import string

HEADERS = {
	"X-Forwarded-Host": "%s.com",
	"X-Forwarded-Port": "%s",
	"X-Forwarded-Server": "%s.com",
	"X-Host": "%s.com",
	"X-Forwarded-Proto": "%s",
	"X-Forwarded-Scheme": "%s",
	"X-Original-URL": "http://%s.com/",
	"X-Original-Host": "%s.com",
	#"Host": "%s.com",
	#"HOST": "%s.com",
	"x-http-method-override": "%s",
	"Referer": "http://%s.com/",
}

def parse_har(in_file):

    result = set()

    with open(in_file) as file:
        data = json.load(file)

    for entry in data['log']['entries']:
        status = entry['response']['status']
        url = entry['request']['url']
        method = entry['request']['method']
        content_type = None
        for header in entry['response']['headers']:
            if header['name'] == "content-type":
                content_type = header['value'].split(";")[0]

        if status == 200 and method == "GET" and content_type in ["text/html", "image/svg+xml", "application/xml", "text/xml", "text/javascript", "application/json", "application/xhtml+xml"]:
            result.add(url)

    return list(result)

def parse_url(url):

	p_url = urlparse(url)
	query = parse_qsl(p_url.query)
	query.append(tuple(['safe',str(random.randrange(1,99999999))]))
	query = p_url._replace(netloc="", scheme="", fragment="", params="", query=urlencode(query))
	query = urlunparse(query)

	return p_url.hostname, query

def scan(target):

    randon_string = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(15))

    for header, value in HEADERS.items():

        domain, path = parse_url(target)
        conn = http.client.HTTPSConnection(domain, 443, timeout=10)
        conn.request("GET", path, headers={header: value % randon_string})
        r = conn.getresponse()

        print("Trying header %s on %s%s with respons %s" % (header, domain, path, r.status))
        for rh, rv in r.getheaders():
        #	print(rv)
            if rv == value:
                print("Header %s reflected by %s" % (rh, header))

        data = r.read()
        match = re.search(randon_string, str(data))
        if match:
            print("\tHeader %s reflected in body on %s%s with status %s" % (header, domain, path, r.status))

    return 0

def main():

    if len(sys.argv) != 2:
        print("Requiers a domain as argument")
        return 0

    for url in parse_har(sys.argv[1]):
    	scan(url)


if __name__ == '__main__':
    sys.exit(main())
