# -*- coding: utf-8 -*-
from __future__ import print_function
from copy import deepcopy
from sipcounter import SIPCounter
from collections import Counter, OrderedDict
import unittest
import os

INVITE = """
INVITE sip:1111@example.com SIP/2.0
From: <sip:2222@example.com>;tag=tag1234
To: <sip:1111@example.com>
Call-ID: aa04470a-e206-491a-8193-e79579456fea
CSeq: 1 INVITE
Subject: test_sipcounter
Via: SIP/2.0/{0} host.example.com:12345;branch=branch1234
Contact: <sip:2222@host.example.com:12345;transport=UDP>
Content-Length: 0
"""

ReINVITE = """
INVITE sip:1111@example.com SIP/2.0
f: <sip:2222@example.com>;tag=tag1234
t: <sip:1111@example.com>;tag=54321fedcba
i: 93793536-fe87-4dea-bc14-b925a00695a0
CSeq: 2 INVITE
s: test_sipcounter
v: SIP/2.0/{0} host.example.com:5060;branch=branch1234
m: <sip:2222@host.example.com:5060;transport=UDP>
l: 0
"""

OK = """
SIP/2.0 200 OK
From: <sip:2222@example.com>;tag=tag1234
To: <sip:1111@example.com>;tag=54321fedcba
Call-ID: 8fda1320-20e4-4d1d-a1ae-d90249b1310b
CSeq: 1 PUBLISH
Subject: test_sipcounter
Via: SIP/2.0/{0} host.example.com:12345;branch=branch1234
Contact: <sip:2222@host.example.com:12345;transport=UDP>
Content-Length: 0
"""


class TestBidir(unittest.TestCase):
    """Test SIPCounter object with direction and host awareness."""

    @classmethod
    def setUpClass(cls):
        cls.dirIn = SIPCounter().dirIn
        cls.dirOut = SIPCounter().dirOut
        cls.dirBoth = SIPCounter().dirBoth
        cls.csvfile = "test_bidir_tocsv.csv"

    @classmethod
    def tearDownClass(cls):
        pass

    @staticmethod
    def merge_two_dicts(x, y):
        z = deepcopy(x)
        z.update(y)
        return z

    @staticmethod
    def get_sipmsg(sipmsg=INVITE, msgdir="IN",
                   srcip="10.0.0.2", srcport=12345,
                   dstip="10.0.0.1", dstport=5060,
                   proto="UDP", msgtype="INVITE", method="INVITE"):
        sipmsg = "\n".join(x.strip() for x in sipmsg.split("\n") if x).format(proto)
        return (sipmsg, msgdir, srcip, srcport, dstip, dstport, proto, msgtype, method)

    def setUp(self):
        self.init_c_simple()
        self.init_c_shuffled()
        self.init_c_canceled()
        self.init_c_publish()
        self.init_c_txferred()
        self.init_c_nodir()

    def init_c_simple(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "UDP", 5060, 12345),
                                {self.dirIn:  Counter({"INVITE": 1,
                                                          "BYE": 1})})])
        self.c_simple = SIPCounter(name="c_simple", sip_filter=["INVITE", "BYE"],
                                   host_filter=["10.0.0.2"], greedy=False, data=data)

    def init_c_shuffled(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "UDP", 5060, 12346),
                                {self.dirIn:  Counter({"INVITE": 1,
                                                          "BYE": 1,
                                                          "200": 1}),
                                self.dirOut: Counter({"ReINVITE": 1,
                                                           "100": 1,
                                                           "180": 1,
                                                           "200": 2})})])
        self.c_shuffled = SIPCounter(name="c_shuffled", sip_filter=["INVITE", "BYE"],
                                     data=data)

    def init_c_canceled(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "TCP", 5070, 12347),
                                {self.dirIn:  Counter({"INVITE": 1,
                                                       "CANCEL": 1,
                                                        "PRACK": 1,
                                                          "ACK": 1}),
                                 self.dirOut: Counter({"100": 1,
                                                       "183": 1,
                                                       "200": 2,
                                                       "487": 1})})])
        self.c_canceled = SIPCounter(name="c_canceled", greedy=False, data=data)

    def init_c_publish(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.3", "TLS", 8888, 6000),
                                {self.dirIn: Counter({"200": 1}),
                                 self.dirOut: Counter({"PUBLISH": 1})})])
        self.c_publish = SIPCounter(name="c_publish", sip_filter=["PUBLISH", "2"],
                                    host_exclude=["10.0.0.2"], known_ports=[8888],
                                    greedy=False, data=data)

    def init_c_txferred(self):
        data = OrderedDict([(("10.0.0.8", "10.0.0.2", "TLS", 5071, 1234),
                                {self.dirIn: Counter({"INVITE": 1,
                                                       "REFER": 1}),
                                 self.dirOut: Counter({"200": 1,
                                                       "202": 1})})])
        self.c_txferred = SIPCounter(name="c_txferred", sip_filter=["INVITE", "REFER", "2"],
                                     known_servers=["10.0.0.8"], data=data)

    def init_c_nodir(self):
        data = OrderedDict([(("10.0.0.8", "10.0.0.2", "TLS", 5071, 1234),
                                {self.dirBoth: Counter({"INVITE": 1})})])
        self.c_nodir = SIPCounter(name="c_nodir", data=data)

    def c_simple_with_zero_bye(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "UDP", 5060, 12345),
                                {self.dirIn:  Counter({"INVITE": 1,
                                                          "BYE": 0})})])
        return SIPCounter(data=data)

    def c_simple_without_bye(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "UDP", 5060, 12345),
                                {self.dirIn:  Counter({"INVITE": 1})})])
        return SIPCounter(data=data)

    def c_simple_without_invite(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "UDP", 5060, 12345),
                                {self.dirIn:  Counter({"BYE": 1})})])
        return SIPCounter(data=data)

    def c_shuffled_without_reinvite(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "UDP", 5060, 12346),
                                {self.dirIn:  Counter({"INVITE": 1,
                                                          "BYE": 1,
                                                          "200": 1}),
                                self.dirOut: Counter({"100": 1,
                                                      "180": 1,
                                                      "200": 2})})])
        return SIPCounter(data=data)

    def c_canceled_without_invite(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "TCP", 5070, 12347),
                        {self.dirIn:  Counter({"CANCEL": 1,
                                                "PRACK": 1,
                                                  "ACK": 1}),
                         self.dirOut: Counter({"100": 1,
                                               "183": 1,
                                               "200": 2,
                                               "487": 1})})])
        return SIPCounter(data=data)

    def c_publish_without_200(self):
        data = OrderedDict([(("10.0.0.1", "10.0.0.3", "TLS", 8888, 6000),
                                {self.dirOut: Counter({"PUBLISH": 1})})])
        return SIPCounter(name="c_publish", sip_filter=["PUBLISH", "2"],
                          host_exclude=["10.0.0.2"], known_ports=[8888],
                          greedy=False, data=data)

    def test_bidir_add_sipmsg_scenario_simple(self):
        c = self.c_simple_without_invite()
        c.add(*self.get_sipmsg(INVITE))
        self.assertEqual(c.data, self.c_simple.data)

    def test_bidir_add_sipmsg_scenario_shuffled_detect_indialog(self):
        c = self.c_shuffled_without_reinvite()
        c.add(*self.get_sipmsg(sipmsg=ReINVITE, msgdir="OUT",
                               srcip="10.0.0.1", srcport=5060,
                               dstip="10.0.0.2", dstport=12346))
        self.assertEqual(c.data, self.c_shuffled.data)

    def test_bidir_add_sipmsg_scenario_canceled_detect_msgdir_proto(self):
        c = self.c_canceled_without_invite()
        t = self.get_sipmsg(sipmsg=INVITE, msgdir="IN", srcport=12347,
                            dstport=5070, proto="TCP")
        sipmsg, _, srcip, srcport, dstip, dstport, _, _, _ = t
        c.add(sipmsg=sipmsg, msgdir=None, srcip=srcip, srcport=srcport,
              dstip=dstip, dstport=dstport, proto=None)
        self.assertEqual(c.data, self.c_canceled.data)

    def test_bidir_add_sipmsg_scenario_publish_detect_msgdir_proto(self):
        c = self.c_publish_without_200()
        c.add(*self.get_sipmsg(sipmsg=OK, srcip="10.0.0.3", srcport=6000,
                                dstport=8888, proto="TLS"))
        self.assertEqual(c.data, self.c_publish.data)

    def test_bidir_check_name_args(self):
        self.assertEqual(self.c_simple.name, "c_simple")
        self.assertEqual(self.c_shuffled.name, "c_shuffled")
        self.assertEqual(self.c_canceled.name, "c_canceled")
        self.assertEqual(self.c_publish.name, "c_publish")
        self.assertEqual(self.c_txferred.name, "c_txferred")

    def test_bidir_check_host_filter_args(self):
        self.assertEqual(self.c_simple.host_filter, set(["10.0.0.2"]))

    def test_bidir_check_host_exclude_args(self):
        self.assertEqual(self.c_publish.host_exclude, set(["10.0.0.2"]))

    def test_bidir_check_known_servers_args(self):
        self.assertEqual(self.c_txferred.known_servers, set(["10.0.0.8"]))

    def test_bidir_check_known_ports_args(self):
        self.assertEqual(self.c_publish.known_ports, set([8888, 5060, 5061]))

    def test_bidir_check_greedy_args(self):
        self.assertFalse(self.c_simple.greedy)
        self.assertTrue(self.c_shuffled.greedy)

    def test_bidir_check_sip_filters_args(self):
        self.assertEqual(self.c_simple.sip_filter, set(["INVITE", "BYE"]))
        self.assertEqual(self.c_canceled.sip_filter, set())
        self.assertEqual(self.c_publish.sip_filter, set(["PUBLISH", "2"]))
        self.assertEqual(self.c_txferred.sip_filter, set(["INVITE", "REFER", "2"]))

    def test_bidir_response_filter(self):
        self.assertEqual(self.c_simple.response_filter, ())
        self.assertEqual(self.c_shuffled.response_filter, ())
        self.assertEqual(self.c_canceled.response_filter, ())
        self.assertEqual(self.c_publish.response_filter, ("2",))
        self.assertEqual(self.c_txferred.response_filter, ("2",))

    def test_bidir_request_filter(self):
        self.assertEqual(self.c_simple.request_filter, set(["INVITE", "ReINVITE", "BYE"]))
        self.assertEqual(self.c_shuffled.request_filter, set(["INVITE", "ReINVITE", "BYE"]))
        self.assertEqual(self.c_canceled.request_filter, set())
        self.assertEqual(self.c_publish.request_filter, set(["PUBLISH"]))
        self.assertEqual(self.c_txferred.request_filter, set(["INVITE", "ReINVITE", "REFER"]))

    def test_bidir_total(self):
        self.assertEqual(self.c_simple.total, 2)
        self.assertEqual(self.c_shuffled.total, 8)
        self.assertEqual(self.c_canceled.total, 9)
        self.assertEqual(self.c_publish.total, 2)
        self.assertEqual(self.c_txferred.total, 4)

    def test_bidir_joinlink(self):
        link_len5 = next(iter(self.c_simple.links()))[:5]
        link_len4 = next(iter(self.c_shuffled.links()))[:4]
        link_len3 = next(iter(self.c_canceled.links()))[:3]
        link_len2 = next(iter(self.c_publish.links()))[:2]
        link_len1 = next(iter(self.c_txferred.links()))[:1]
        exp_len5 = "10.0.0.1=UDP=5060=12345=10.0.0.2".ljust(47)
        exp_len4 = "10.0.0.1-UDP-5060-10.0.0.2".ljust(30)
        exp_len3 = "10.0.0.1-TCP-10.0.0.2".ljust(30)
        exp_len2 = "10.0.0.1-10.0.0.3".ljust(25)
        exp_len1 = "10.0.0.8".ljust(20)
        self.assertEqual(self.c_simple._joinlink(link_len5, sep="="),  exp_len5)
        self.assertEqual(self.c_shuffled._joinlink(link_len4, width=30), exp_len4)
        self.assertEqual(self.c_canceled._joinlink(link_len3, width=30), exp_len3)
        self.assertEqual(self.c_publish._joinlink(link_len2, width=25), exp_len2)
        self.assertEqual(self.c_txferred._joinlink(link_len1, width=20), exp_len1)

    def test_bidir_msgdirs(self):
        self.assertEqual(self.c_simple.msgdirs(), (self.dirOut, self.dirIn))
        self.assertEqual(self.c_shuffled.msgdirs(), (self.dirOut, self.dirIn))

    def test_bidir_makelink(self):
        c1_args = ("10.0.0.2", 12345, "10.0.0.1", 5060, "UDP")
        exp1 = (("10.0.0.1", "10.0.0.2", "UDP", 5060, 12345), self.dirIn)
        c2_args = ("10.0.0.1", 5060, "10.0.0.2", 12346, "UDP")
        exp2 = (("10.0.0.1", "10.0.0.2", "UDP", 5060, 12346), self.dirOut)
        c3_args = ("10.0.0.1", 5070, "10.0.0.2", 12347, "TCP")
        exp3 = (("10.0.0.1", "10.0.0.2", "TCP", 5070, 12347), self.dirOut)
        self.assertEqual(self.c_simple._makelink("IN", *c1_args), exp1)
        self.assertEqual(self.c_shuffled._makelink("OUT", *c2_args), exp2)
        self.assertEqual(self.c_canceled._makelink(None, *c3_args), exp3)

    def test_bidir_gettype_sipmsg_request(self):
        sipmsg = self.get_sipmsg(sipmsg=ReINVITE, proto="TCP")[0]
        exp = ("ReINVITE", "INVITE", "TCP")
        self.assertEqual(self.c_shuffled._gettype(sipmsg), exp)

    def test_bidir_gettype_sipmsg_response(self):
        sipmsg = self.get_sipmsg(sipmsg=OK)[0]
        exp = ("200", "PUBLISH", "UDP")
        self.assertEqual(self.c_publish._gettype(sipmsg), exp)

    def test_bidir_gettype_msgtype_method_proto(self):
        d = {"msgtype": "200", "method": "PUBLISH", "proto": "TCP"}
        exp = ("200", "PUBLISH", "TCP")
        self.assertEqual(self.c_publish._gettype(**d), exp)

    def test_bidir_is_host_ignorable(self):
        self.assertTrue(self.c_simple.is_host_ignorable("10.0.0.8", "10.0.0.3"))
        self.assertFalse(self.c_shuffled.is_host_ignorable("10.0.0.8", "10.0.0.3"))
        self.assertFalse(self.c_publish.is_host_ignorable("10.0.0.1", "10.0.0.3"))
        self.assertTrue(self.c_publish.is_host_ignorable("10.0.0.1", "10.0.0.2"))

    def test_bidir_is_sipmsg_ignorable(self):
        self.assertTrue(self.c_simple.is_sipmsg_ignorable("", ""))
        self.assertFalse(self.c_simple.is_sipmsg_ignorable("ReINVITE", "INVITE"))
        self.assertTrue(self.c_simple.is_sipmsg_ignorable("200", "BYE"))
        self.assertFalse(self.c_shuffled.is_sipmsg_ignorable("200", "BYE"))
        self.assertFalse(self.c_canceled.is_sipmsg_ignorable("200", "OPTIONS"))
        self.assertTrue(self.c_publish.is_sipmsg_ignorable("404", "PUBLISH"))
        self.assertTrue(self.c_txferred.is_sipmsg_ignorable("503", "INVITE"))

    def test_bidir_add_sipmsg_sipmsg_ignorable_rv_0(self):
        rv = self.c_simple.add(*self.get_sipmsg(sipmsg=OK))
        self.assertEqual(rv, 0)

    def test_bidir_add_sipmsg_sipmsg_not_ignorable_rv_1(self):
        rv = self.c_publish.add(*self.get_sipmsg(sipmsg=OK, srcip="10.0.0.3",
                                                 srcport=6000, dstport=8888))
        self.assertEqual(rv, 1)

    def test_bidir_add_msgtype_method_proto(self):
        c = self.c_simple_without_invite()
        t = self.get_sipmsg(sipmsg=INVITE)
        _, msgdir, srcip, srcport, dstip, dstport, proto, msgtype, method = t
        rv = c.add(msgdir=msgdir, srcip=srcip, srcport=srcport, dstip=dstip,
                   dstport=dstport, proto=proto, msgtype=msgtype, method=method)
        self.assertEqual(c.data, self.c_simple.data)
        self.assertEqual(rv, 1)

    def test_bidir_update(self):
        c = self.c_simple_without_invite()
        data = OrderedDict([(("10.0.0.1", "10.0.0.2", "UDP", 5060, 12345),
                                {self.dirIn:  Counter({"INVITE": 1})})])
        c.update(data=data)
        self.assertEqual(c.data, self.c_simple.data)

    def test_bidir_subtract_link_removed(self):
        self.c_simple.subtract(data=self.c_simple.data)
        self.assertEqual(self.c_simple.data, OrderedDict())

    def test_bidir_subtract_nothing_removed(self):
        data = self.c_simple.data
        self.c_simple.subtract(data=self.c_shuffled.data)
        self.assertEqual(self.c_simple.data, data)

    def test_bidir_subtract_msgtye_removed(self):
        c = self.c_simple_without_invite()
        exp = self.c_simple_without_bye()
        self.c_simple.subtract(data=c.data)
        self.assertEqual(self.c_simple.data, exp.data)

    def test_bidir_subtract_no_compact_msgtye_zeroed(self):
        c = self.c_simple_without_invite()
        exp = self.c_simple_with_zero_bye()
        self.c_simple.subtract(data=c.data, compact=False)
        self.assertEqual(self.c_simple.data, exp.data)

    def test_bidir__add__(self):
        combined = self.c_simple + self.c_shuffled
        exp = self.merge_two_dicts(self.c_simple.data, self.c_shuffled.data)
        self.assertEqual(combined.data, exp)
        self.assertEqual(combined.sip_filter, self.c_simple.sip_filter)
        self.assertEqual(combined.host_filter, self.c_simple.host_filter)
        self.assertEqual(combined.host_exclude, self.c_simple.host_exclude)
        self.assertEqual(combined.known_servers, self.c_simple.known_servers)
        self.assertEqual(combined.known_ports, self.c_simple.known_ports)
        self.assertEqual(combined.name, self.c_simple.name)

    def test_bidir__add__type_mismatch(self):
        with self.assertRaises(TypeError):
            _ = self.c_simple + self.c_nodir

    def test_bidir__sub__link_removed(self):
        diff = self.c_simple - self.c_simple
        self.assertEqual(diff.data, OrderedDict())
        self.assertEqual(diff.sip_filter, self.c_simple.sip_filter)
        self.assertEqual(diff.host_filter, self.c_simple.host_filter)
        self.assertEqual(diff.host_exclude, self.c_simple.host_exclude)
        self.assertEqual(diff.known_servers, self.c_simple.known_servers)
        self.assertEqual(diff.known_ports, self.c_simple.known_ports)
        self.assertEqual(diff.name, self.c_simple.name)

    def test_bidir__sub__nothing_removed(self):
        diff = self.c_simple - self.c_shuffled
        self.assertEqual(diff.data, self.c_simple.data)

    def test_bidir__sub__msgtye_removed(self):
        c = self.c_simple_without_invite()
        exp = self.c_simple_without_bye()
        diff = self.c_simple - c
        self.assertEqual(diff.data, exp.data)

    def test_bidir__sub__type_mismatch(self):
        with self.assertRaises(TypeError):
            _ = self.c_simple - self.c_nodir

    def test_bidir__iadd__(self):
        self.c_simple += self.c_shuffled
        exp = self.merge_two_dicts(self.c_simple.data, self.c_shuffled.data)
        self.assertEqual(self.c_simple.data, exp)

    def test_bidir__iadd__type_mismatch(self):
        with self.assertRaises(TypeError):
            self.c_simple += self.c_nodir

    def test_bidir__isub__link_removed(self):
        self.c_simple -= self.c_simple
        self.assertEqual(self.c_simple.data, OrderedDict())

    def test_bidir__isub__nothing_removed(self):
        data = self.c_simple.data
        self.c_simple -= self.c_shuffled
        self.assertEqual(self.c_simple.data, data)

    def test_bidir__isub__msgtye_removed(self):
        c = self.c_simple_without_invite()
        exp = self.c_simple_without_bye()
        self.c_simple -= c
        self.assertEqual(self.c_simple.data, exp.data)

    def test_bidir__isubb__type_mismatch(self):
        with self.assertRaises(TypeError):
            self.c_simple -= self.c_nodir

    def test_bidir_compare(self):
        self.assertTrue(self.c_canceled > self.c_shuffled)
        self.assertTrue(self.c_canceled >= self.c_simple)
        self.assertTrue(self.c_publish < self.c_txferred)
        self.assertTrue(self.c_publish <= self.c_simple)
        self.assertTrue(self.c_simple != self.c_shuffled)
        self.assertTrue(self.c_publish == self.c_simple)

    def test_bidir_sum(self):
        combined = self.c_simple + self.c_shuffled
        self.assertEqual(combined.sum(), 10)
        self.assertEqual(combined.sum(axis=0), [2, 8])
        self.assertEqual(combined.sum(axis=1), [0, 2, 1, 0, 0, 2, 1, 0, 1, 0, 2, 1])

    def test_bidir_max(self):
        combined = self.c_simple + self.c_shuffled
        self.assertTrue(combined.max(), 2)
        self.assertTrue(combined.sum(axis=0), [1, 2])
        self.assertTrue(combined.sum(axis=1), [0, 2, 1, 0, 0, 2, 1, 0, 1, 0, 2, 1])

    def test_bidir_tocolumns(self):
        combined = self.c_simple + self.c_shuffled
        exp = OrderedDict([(('10.0.0.1', '10.0.0.2', 'UDP', 5060, 12345),
                                [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
                           (('10.0.0.1', '10.0.0.2', 'UDP', 5060, 12346),
                                [0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 2, 1])])
        self.assertEqual(combined.tocolumns(), exp)

    def test_bidir_tostring_depth_4(self):
        combined = self.c_simple + self.c_shuffled
        exp = "c_simple                      INVITE   ReINVITE    BYE       100       180       200    TOTAL\n                            ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- ---> <---\n10.0.0.1-UDP-5060-10.0.0.2     0    2    1    0    0    2    1    0    1    0    2    1    10\nSUMMARY                        0    2    1    0    0    2    1    0    1    0    2    1    10"
        self.assertEqual(combined.tostring(), exp)

    def test_bidir_groupby_depth_4(self):
        combined = self.c_simple + self.c_shuffled + self.c_canceled
        exp = OrderedDict([(('10.0.0.1', '10.0.0.2', 'TCP', 5070),
                                {self.dirIn: Counter({'INVITE': 1,
                                                       'PRACK': 1,
                                                      'CANCEL': 1,
                                                         'ACK': 1}),
                                 self.dirOut: Counter({'200': 2,
                                                       '100': 1,
                                                       '183': 1,
                                                       '487': 1})}),
                           (('10.0.0.1', '10.0.0.2', 'UDP', 5060),
                                {self.dirIn: Counter({'INVITE': 2,
                                                         'BYE': 2,
                                                         '200': 1}),
                                 self.dirOut: Counter({'200': 2,
                                                       '100': 1,
                                                       '180': 1,
                                                  'ReINVITE': 1})})])

        self.assertTrue(combined.groupby(), exp)

    def test_bidir_groupby_depth_2(self):
        combined = self.c_simple + self.c_shuffled + self.c_canceled
        exp = OrderedDict([(('10.0.0.1', '10.0.0.2'),
                            {self.dirIn: Counter({'INVITE': 3,
                                                     'BYE': 2,
                                                     '200': 1,
                                                   'PRACK': 1,
                                                  'CANCEL': 1,
                                                     'ACK': 1}),
                             self.dirOut: Counter({'200': 4,
                                                   '100': 2,
                                                   '180': 1,
                                              'ReINVITE': 1,
                                                   '183': 1,
                                                   '487': 1})})])
        self.assertEqual(combined.groupby(depth=2), exp)

    def test_bidir_most_common_depth_4_n_1(self):
        combined = self.c_simple + self.c_shuffled + self.c_canceled
        exp = OrderedDict([(('10.0.0.1', '10.0.0.2', 'UDP', 5060),
                                {self.dirIn: Counter({'INVITE': 2,
                                                         'BYE': 2,
                                                         '200': 1}),
                                 self.dirOut: Counter({'200': 2,
                                                       '100': 1,
                                                       '180': 1,
                                                  'ReINVITE': 1})})])
        self.assertEqual(combined.most_common(n=1), exp)

    def test_bidir_most_common_depth_5_n_2(self):
        combined = self.c_simple + self.c_shuffled + self.c_canceled
        exp = OrderedDict([(('10.0.0.1', '10.0.0.2', 'TCP', 5070, 12347),
                                {self.dirIn: Counter({'INVITE': 1,
                                                       'PRACK': 1,
                                                      'CANCEL': 1,
                                                         'ACK': 1}),
                                 self.dirOut: Counter({'200': 2,
                                                       '100': 1,
                                                       '183': 1,
                                                       '487': 1})}),
                           (('10.0.0.1', '10.0.0.2', 'UDP', 5060, 12346),
                                {self.dirIn: Counter({'INVITE': 1,
                                                         '200': 1,
                                                         'BYE': 1}),
                                 self.dirOut: Counter({'200': 2,
                                                       '100': 1,
                                                       '180': 1,
                                                  'ReINVITE': 1})})])
        self.assertEqual(combined.most_common(n=2, depth=5), exp)

    def test_bidir_tocsv_depth_5_with_header(self):
       combined = self.c_simple + self.c_shuffled
       combined.tocsv(filepath=self.csvfile)
       size = os.stat(self.csvfile).st_size
       self.assertEqual(size, 273)
       os.remove(self.csvfile)


if __name__ == "__main__":
    unittest.main()
