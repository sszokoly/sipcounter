import unittest
from sipcounter import SIPCounter

invite_tls = 'INVITE sip\r\nCSeq: 2 INVITE\r\nVia: SIP/2.0/TLS 1\r\nTo: 2\r\n'
invite_tcp = 'INVITE sip\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/TCP 1\r\nTo: 1\r\n'
ok200_tls = 'SIP/2.0 200 OK\r\nCSeq: 2 INIVTE\r\nVia: SIP/2.0/TLS 2\r\n'
ok200_tcp = 'SIP/2.0 200 OK\r\nCSeq: 1 INIVTE\r\nVia: SIP/2.0/TCP 1\r\n'
server1 = '1.1.1.1'
server2 = '1.1.1.2'
server1_port = '5061'
server2_port = '5070'
client1 = '2.2.2.1'
client2 = '2.2.2.2'
client_port1 = '1234'
client_port2 = '23456'

class TestBidir(unittest.TestCase):
    """
    Test the CLI API.
    """

    def setUpClass(self):
        self.counter1_bidir_args = SIPCounter(name='bidir1',
                                         sip_filter=set(['INIVTE', '2']),
                                         host_filter=set([server1]))
        self.counter2_bidir_args = SIPCounter(name='bidir2',
                                         host_filter=set([server2]))

    def test_add_bidir(self):
        self.counter1_bidir_args.add(invite_tls, 'IN',
                                     server1, server1_port,
                                     client1, client_port1)
        self.counter2_bidir_args.add(invite_tcp, 'IN',
                                     server2, server1_port,
                                     client2, client_port2)


