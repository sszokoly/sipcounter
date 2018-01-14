import random
from SIPCounter import SIPCounter

req = '%s sip\r\nCSeq: 1 %s\r\nVia: SIP/2.0/%s 1\r\nTo: 1;%s\r\n'
resp = 'SIP/2.0 %s Bla\r\nCSeq: 1 %s\r\nVia: SIP/2.0/%s 1\r\n'
requests = ['INVITE', 'ReINVITE', 'BYE', 'CANCEL']
responses = ['500', '503', '600']
tags = ['tag=1', '']
servers = [('1.1.1.1', 'TLS', '5061'),
           ('1.1.1.1', 'TCP', '5060'),
           ('1.1.1.2', 'TCP', '5060'),
           ('1.1.1.2', 'TCP', '5062'),
           ('1.1.1.2', 'UDP', '5060')]
clients = [('2.2.2.1', '33456'),
           ('2.2.2.1', '33457'),
           ('2.2.2.2', '33458'),
           ('2.2.2.3', '33459')]
protocols = ['TCP', 'TLS', 'UDP']

def request_generator():
    while 1: 
        request = random.choice(requests)
        server = random.choice(servers)
        client = random.choice(clients)
        tag = random.choice(tags)
        sipmsg = req % (request, request, server[1], tag)
        if random.randrange(0, 2):
            srcip, srcport, dstip, dstport, proto = client[0], client[1], server[0], server[2], server[1]
        else:
            srcip, srcport, dstip, dstport, proto = server[0], server[2], client[0], client[1], server[1]
        yield (sipmsg, srcip, srcport, dstip, dstport, proto)

def response_generator():
    while 1:
        response = random.choice(responses)
        request = random.choice(requests)
        server = random.choice(servers)
        client = random.choice(clients)
        sipmsg = req % (response, request, server[1], '')
        if random.randrange(0, 2):
            srcip, srcport, dstip, dstport, proto = server[0], server[2], client[0], client[1], server[1]
        else:
            srcip, srcport, dstip, dstport, proto = client[0], client[1], server[0], server[2], server[1]
        yield (sipmsg, srcip, srcport, dstip, dstport, proto)

request = request_generator()
response = response_generator()
sipcounter = SIPCounter(name='SIP Server 1.1.1.{1,2}',
                        known_servers=set(['1.1.1.1', '1.1.1.2']),
                        known_ports=set(['5062']))

for x in xrange(0,9000):
    sipmsg, srcip, srcport, dstip, dstport, proto = request.next()
    sipcounter.add(sipmsg, None, srcip, srcport, dstip, dstport, proto)

for x in xrange(0,9000):
    sipmsg, srcip, srcport, dstip, dstport, proto = response.next()
    sipcounter.add(sipmsg, None, srcip, srcport, dstip, dstport, proto)

print(sipcounter.pprint(title='2018-0101 01:01:00'))
print(sipcounter.pprint(title='2018-0101 01:01:00', depth=2))
print(sipcounter.pprint(title='Top 3', data=sipcounter.most_common(3, depth=2)))
print request.next()