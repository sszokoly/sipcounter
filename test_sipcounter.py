import unittest
from sipcounter import SIPCounter
from collections import defaultdict, Counter, OrderedDict

invite_tls = 'INVITE sip\r\nCSeq: 2 INVITE\r\nVia: SIP/2.0/TLS 1\r\nTo: 2\r\n'
invite_tcp = 'INVITE sip\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/TCP 1\r\nTo: 1\r\n'
ok200_tls = 'SIP/2.0 200 OK\r\nCSeq: 2 INIVTE\r\nVia: SIP/2.0/TLS 2\r\n'
ok200_tcp = 'SIP/2.0 200 OK\r\nCSeq: 1 INIVTE\r\nVia: SIP/2.0/TCP 1\r\n'
server = '1.1.1.1'
server_port_tls = '5061'
server_port_tcp = '5070'
client1 = '2.2.2.1'
client2 = '2.2.2.2'
client_port1 = '1234'
client_port2 = '23456'

class TestBidir(unittest.TestCase):
    """
    Test the CLI API.
    """

    def setUp(self):
        self.c1_bidir_args = SIPCounter(name='c1_bidir_args',
                                        #sip_filter=set(['INVITE', '2']),
                                        host_filter=set([server]))
        self.c2_bidir_args = SIPCounter(name='c2_bidir_args',
                                        host_filter=set([server]))
        self.c3_bidir = SIPCounter(name='c3_bidir',
                                   sip_filter=set(['INIVTE', '2']),
                                   host_filter=set([server]))
        self.c4_bidir = SIPCounter(name='c4_bidir',
                                   host_filter=set([server]))
        self.c5_nodir = SIPCounter(name='c5_nodir',
                                   host_filter=set([server]))
        self.c6_nodir = SIPCounter(name='c6_nodir',
                                   host_filter=set([server]))

    def test_add_bidir_args(self):
        self.c1_bidir_args.add(invite_tls, 'OUT',
                               server, server_port_tls,
                               client1, client_port1)
        self.c1_bidir_args.add(ok200_tls, None,
                               client1, client_port1,
                               server, server_port_tls)
        self.c2_bidir_args.add(invite_tcp, 'IN',
                               client2, client_port2,
                               server, server_port_tcp)
        self.c2_bidir_args.add(ok200_tls, None,
                               server, server_port_tcp,
                               client2, client_port2)
        c1_keys = ('1.1.1.1', '2.2.2.1', 'tls', '5061', '1234')
        c1_values = {'->': Counter({'INVITE': 1}), '<-': Counter({'200': 1})}
        c2_keys = [('1.1.1.1', '2.2.2.2', 'tcp', '5061', '23456')]
        c2_values = [{'->': Counter({'INVITE': 1}), '<-': Counter({'200': 1})}]
        print self.c1_bidir_args.reReINVITE.search('200')
        #self.assertEqual(self.c1_bidir_args.data.keys()[0], c1_keys)
        #self.assertEqual(self.c1_bidir_args.data.values()[0], c1_values)
        #self.assertEqual(self.c2_bidir_args.data.keys(), c2_keys)
        #self.assertEqual(self.c2_bidir_args.data.values(), c2_values)





if __name__ == '__main__':
    unittest.main()