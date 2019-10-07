#!/usr/bin/env python3
import requests
import csv

#data_url = 'https://dnsthought.nlnetlabs.nl/raw/latest.csv'
url = 'https://dnsthought.nlnetlabs.nl/raw/2019-09-25.csv'

#probes_url = 

'''
"datetime","probe ID","probe resolver","o-o.myaddr.l.google.com TXT","whoami.akamai.net A","ripe-hackathon6.nlnetlabs.nl AAAA","can_ipv6","can_tcp","cap_tcp6","ecs_mask","ecs_mask6","does_ecs","does_flagday","does_qnamemin","doesnt_qnamemin","hijacked #0","hijacked #1","hijacked #2","hijacked #3","does_nxdomain","doesnt_nxdomain","has_ta_19036","hasnt_ta_19036","has_ta_20326","hasnt_ta_20326","can_rsamd5","cannot_rsamd5","broken_rsamd5","can_dsa","cannot_dsa","broken_dsa","can_rsasha1","cannot_rsasha1","broken_rsasha1","can_dsansec3","cannot_dsansec3","broken_dsansec3","can_rsansec3","cannot_rsansec3","broken_rsansec3","can_rsasha256","cannot_rsasha256","broken_rsasha256","can_rsasha512","cannot_rsasha512","broken_rsasha512","can_eccgost","cannot_eccgost","broken_eccgost","can_ecdsa256","cannot_ecdsa256","broken_ecdsa256","can_ecdsa384","cannot_ecdsa384","broken_ecdsa384","can_ed25519","cannot_ed25519","broken_ed25519","can_ed448","cannot_ed448","broken_ed448","can_gost","cannot_gost","broken_gost","can_sha284","cannot_sha284","broken_sha284"
'''


out = {}

with requests.Session() as s:
    download = s.get(url)
    decoded_content = download.content.decode('utf-8')
    cr = csv.DictReader(decoded_content.splitlines(), delimiter=',')
    #my_list = list(cr)
    for row in list(cr):
        score = { # percentages
            'security': 0,
            'privacy': 0,
            #TODO 'performance': 0,
            'compliance': 0
        }
        # SECURITY
        if row['can_rsasha256'] == "1": # high score because this signifies that you can dnssec and reach root zone
            score['security'] += 60
        for dnssec in ('can_ed448', 'can_ed25519', 'can_ecdsa384', 'can_ecdsa256', 'can_rsasha512'): #TODO , 'can_sha1nsec3'):
            if row[ dnssec ] == "1":
                score['security'] += 3
        if row['can_rsasha1'] == "1": # slightly weaker than the rest of dnssec
                score['security'] += 2
        if row['doesnt_nxdomain'] == "1":
                score['security'] += 10
        if row['has_ta_20326'] == "1": #TODO check with WT
                score['security'] += 10
        # PRIVACY
        if row['does_qnamemin'] == "1":
            score['privacy'] += 50 # ecs_privacy , dns-over-tls: then 25%
        if row['does_ecs'] == "0": 
            score['privacy'] += 50 # ecs_privacy , dns-over-tls: then 25%
        #TODO ecs_privacy option
        #TODO dns over tls
        # PERFORMANCE
        #TODO
        # COMPLIANCE
        if row['does_flagday'] == "1":
            score['compliance'] += 25
        if row['can_tcp'] == "1":
            score['compliance'] += 25
        if row['can_rsasha256'] == "1": # this signifies that you can dnssec and reach root zone
            score['compliance'] += 25
        if row['can_ipv6'] == "1":
            score['compliance'] += 25
        # RESULT
        print(
            "{} {} {}".format(
                row["probe ID"],row["probe resolver"], score
            )
        )
'''
"datetime","probe ID","probe resolver","o-o.myaddr.l.google.com TXT","whoami.akamai.net A","ripe-hackathon6.nlnetlabs.nl AAAA","can_ipv6","can_tcp","cap_tcp6","ecs_mask","ecs_mask6","does_ecs","does_flagday","does_qnamemin","doesnt_qnamemin","hijacked #0","hijacked #1","hijacked #2","hijacked #3","does_nxdomain","doesnt_nxdomain","has_ta_19036","hasnt_ta_19036","has_ta_20326","hasnt_ta_20326","can_rsamd5","cannot_rsamd5","broken_rsamd5","can_dsa","cannot_dsa","broken_dsa","can_rsasha1","cannot_rsasha1","broken_rsasha1","can_dsansec3","cannot_dsansec3","broken_dsansec3","can_rsansec3","cannot_rsansec3","broken_rsansec3","can_rsasha256","cannot_rsasha256","broken_rsasha256","can_rsasha512","cannot_rsasha512","broken_rsasha512","can_eccgost","cannot_eccgost","broken_eccgost","can_ecdsa256","cannot_ecdsa256","broken_ecdsa256","can_ecdsa384","cannot_ecdsa384","broken_ecdsa384","can_ed25519","cannot_ed25519","broken_ed25519","can_ed448","cannot_ed448","broken_ed448","can_gost","cannot_gost","broken_gost","can_sha284","cannot_sha284","broken_sha284"
'''
