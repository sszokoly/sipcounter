from __future__ import print_function
import unittest
import uuid
import time
from collections import Counter, OrderedDict
from functools import partial, reduce
from sipcounter import SIPCounter
from random import randrange

roledir = {"c": "IN", "s": "OUT"}

scenarios = {
    "simple": (
        ("INVITE", "c"),
        ("100", "s"),
        ("180", "s"),
        ("200", "s"),
        ("ACK", "c"),
        ("BYE", "c"),
        ("200", "s"),
    ),
    "shuffled": (
        ("INVITE", "c"),
        ("100", "s"),
        ("180", "s"),
        ("200", "s"),
        ("ACK", "c"),
        ("INVITE", "s"),
        ("200", "c"),
        ("ACK", "s"),
        ("BYE", "c"),
        ("200", "s"),
    ),
    "canceled": (
        ("INVITE", "c"),
        ("100", "s"),
        ("183", "s"),
        ("PRACK", "c"),
        ("200", "s"),
        ("CANCEL", "c"),
        ("200", "s"),
        ("487", "s"),
        ("ACK", "c"),
    ),
    "transferred": (
        ("INVITE", "c"),
        ("100", "s"),
        ("180", "s"),
        ("200", "s"),
        ("ACK", "c"),
        ("REFER", "c"),
        ("202", "s"),
        ("BYE", "s"),
        ("200", "c"),
    ),
    "moved": (
        ("INVITE", "c"),
        ("100", "s"),
        ("302", "s"),
        ("ACK", "c"),
    ),
    "auth": (
        ("INVITE", "c"),
        ("100", "s"),
        ("401", "s"),
        ("ACK", "c"),
    ),
    "forbidden": (
        ("INVITE", "c"),
        ("100", "s"),
        ("403", "s"),
        ("ACK", "c"),
    ),
    "publish": (
        ("PUBLISH", "s"),
        ("200", "c"),
    ),
    "notify": (
        ("NOTIFY", "s"),
        ("200", "c"),
    ),
    "subscribe": (
        ("SUBSCRIBE", "c"),
        ("202", "s"),
    ),
    "options": (
        ("OPTIONS", "c"),
        ("200", "s")
    ),
    "server_error": (
        ("INVITE", "c"),
        ("100", "s"),
        ("500", "s"),
        ("ACK", "c"),
    ),
    "global_error": (
        ("INVITE", "c"),
        ("100", "s"),
        ("603", "s"),
        ("ACK", "c"),)
    ,
    "client_only": (
        ("INVITE", "c"),
        ("INVITE", "c"),
        ("INVITE", "c")
    ),
}

response_descr = {
    "100": "Trying",
    "180": "Ringing",
    "183": "Session Progress",
    "200": "OK",
    "202": "ACCEPTED",
    "302": "Moved Temporarily",
    "401": "Unauthorized",
    "403": "Forbidden",
    "487": "Request Terminated",
    "500": "500 Server Internal Error",
    "603": "Decline",
}


def randipport():
    """Generates random IP address and port number"""
    first = [str(randrange(1, 255))]
    rest = [str(randrange(0, 255)) for _ in range(4)]
    ip = ".".join(first + rest)
    port = str(randrange(1025, 65536))
    return ip, port

def expectations(
    scenario,
    client_ip="",
    client_port="",
    server_ip="",
    server_port="",
    msgdir=False,
    proto="",
    iterations=1,
):
    """Returns the expected 'data' dict of a SIPCounter for a scenario."""
    c = SIPCounter()
    counter, counters = {}, {}

    if not server_ip:
        server_ip = c.local
    if not client_ip:
        client_ip = c.remote
    if proto is None:
        proto = "TCP"
    elif not proto:
        proto = "UDP"
    else:
        proto = proto.upper()

    key = (server_ip, client_ip, proto, server_port, client_port)

    for _ in range(iterations):
        response_seen = False
        for msgtype, role in scenario:
            if msgtype == "INVITE":
                if response_seen:
                    msgtype = "ReINVITE"
            else:
                response_seen = True
            try:
                counter[role].update([msgtype])
            except KeyError:
                counter[role] = Counter()
                counter[role].update([msgtype])
    if msgdir:
        try:
            counters[c.dirOut] = counter["s"]
        except:
            pass
        try:
            counters[c.dirIn] = counter["c"]
        except:
            pass
    else:
        counters[c.dirBoth] = counter["c"] + counter["s"]

    return {key: counters}

def merge_expectations(
    expectation1, expectation2, subtract=False, compact=True, depth=5
):
    """Returns the addition/subtraction of two SIPCounter 'data' dict."""
    merged = {}

    for k, v in expectation1.items():
        for d, c in v.items():
            merged.setdefault(k[:depth], {}).setdefault(d, Counter()).update(c)

    if not subtract:
        for k, v in expectation2.items():
            for d, c in v.items():
                merged.setdefault(k[:depth], {}).setdefault(d, Counter()).update(c)
        return merged

    for k, v in expectation2.items():
        if k[:depth] not in merged:
            continue
        for d, c in v.items():
            if d in merged[k[:depth]]:
                merged[k[:depth]][d].subtract(c)

    if compact:
        compacted = {}
        for k, v in merged.items():
            for k2, v2 in v.items():
                for k3, v3 in v2.items():
                    if v3 > 0:
                        (
                            compacted.setdefault(k[:depth], {})
                            .setdefault(k2, Counter())
                            .update({k3: v3})
                        )
        return compacted

    return merged


def sip_generator(
    scenarios=scenarios,
    response_descr=response_descr,
    scenario_iterations=None,
    client_ip="",
    client_port="",
    server_ip="",
    server_port="",
    proto="",
    initdir="IN",
    compact=False,
    bad=False,
    sleep=0,
    leadinglines="",
    callee="1111",
    caller="2222",
):
    """Returns a SIP message generator for a scenario from scenarios."""
    req_uri = "{leadinglines}{method} sip:{callee}@example.com SIP/2.0"
    resp_status = "{leadinglines}SIP/2.0 {status}"

    template_long = """
        From: <sip:2222@example.com>;tag=tag1234
        To: <sip:{callee}@example.com>{to_tag}
        Call-ID: {callid}
        CSeq: {cseq} {method}
        Subject: test_sipcounter
        Via: SIP/2.0/{proto} {sender_ip}:{sender_port};branch=branch1234
        Contact: <sip:{caller}@{sender_ip}:{sender_port};transport={proto}>
        Content-Length: 0
        """

    template_comp = """
        f: <sip:2222@example.com>;tag=tag1234
        t: <sip:{callee}@example.com>{to_tag}
        i: {callid}
        CSeq: {cseq} {method}
        s: test_sipcounter
        v: SIP/2.0/{proto} {sender_ip}:{sender_port};branch=branch1234
        m: <sip:{caller}@{sender_ip}:{sender_port};transport={proto}>
        l: 0
        """

    template_bad = """
        From: <sip:2222@example.com>;tag=tag1234
        To: <sip:{callee}@example.com>{to_tag}
        Call-ID: {callid}
        CSeq: {cseq}
        Subject: test_sipcounter
        Via: SIP/2.0/{proto} {sender_ip}:{sender_port};branch=branch1234
        Contact: <sip:{caller}@{sender_ip}:{sender_port};transport={proto}>
        Content-Length: 0
        """

    builtin_scenarios = {
        "test": (("INVITE", "c"), ("100", "s"), ("404", "s"), ("ACK", "c"))
    }

    builtin_response_descr = {"100": "Trying", "401": "Not Found"}

    if not isinstance(scenarios, dict):
        scenarios = builtin_scenarios

    if not isinstance(response_descr, dict):
        response_descr = builtin_response_descr

    if scenario_iterations is None:
        scenario_iterations = dict((k, 1) for k in scenarios.keys())

    if compact:
        template = "\n".join(x.strip() for x in template_comp.split("\n") if x)
    elif bad:
        template = "\n".join(x.strip() for x in template_bad.split("\n") if x)
    else:
        template = "\n".join(x.strip() for x in template_long.split("\n") if x)

    for scenario, iterations in scenario_iterations.items():
        cseq = randrange(1000)

        for _ in range(iterations):
            roledir, to_tag = None, ""

            for msgtype, role in scenarios[scenario]:
                if roledir is None:
                    other_role = (set(["c", "s"]) - set([role])).pop()
                    other_dir = (set(["IN", "OUT"]) - set([initdir])).pop()
                    roledir = {role: initdir, other_role: other_dir}

                if msgtype.isdigit():
                    firstline = resp_status
                    status = " ".join((msgtype, response_descr.get(msgtype, "")))
                    if int(msgtype) > 100 and not to_tag:
                        to_tag = ";tag=54321fedcba"
                else:
                    firstline = req_uri
                    method = msgtype
                    status = ""
                    if msgtype != "ACK":
                        cseq += 1

                if role == "s":
                    sender_ip = server_ip
                    sender_port = server_port
                    receiver_ip = client_ip
                    receiver_port = client_port
                else:
                    sender_ip = client_ip
                    sender_port = client_port
                    receiver_ip = server_ip
                    receiver_port = server_port

                msgdir = roledir[role]
                placeholders = {
                    "caller": caller,
                    "callee": callee,
                    "leadinglines": leadinglines,
                    "method": method,
                    "status": status,
                    "sender_ip": sender_ip or "10.1.1.1",
                    "sender_port": sender_port or "65535",
                    "callid": uuid.uuid4(),
                    "to_tag": to_tag,
                    "proto": proto or "UDP",
                    "cseq": cseq,
                }

                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                sipmsg = "\n".join((firstline, template)).format(**placeholders)
                yield (
                    timestamp,
                    sipmsg,
                    msgdir,
                    sender_ip,
                    sender_port,
                    receiver_ip,
                    receiver_port,
                    proto,
                )
                time.sleep(sleep)


class TestBidir(unittest.TestCase):
    """Test SIPCounter object"""

    @classmethod
    def setupClass(cls):
        pass

    def test_create_counter_with_default_values(self):
        c1 = SIPCounter()
        self.assertEqual(c1.name, "")
        self.assertEqual(c1.sip_filter, set([".*"]))
        self.assertEqual(c1.host_filter, set())
        self.assertEqual(c1.known_servers, set())
        self.assertEqual(c1.known_ports, set(["5061", "5060"]))
        self.assertEqual(c1.data, {})

    def test_create_counter_with_none_default_values(self):
        sip_filter = ["INVITE", "200"]
        host_filter = ["10.0.0.2"]
        known_servers = ["10.0.0.1"]
        known_ports = ["5070"]
        name = "c1"
        link = ("10.0.0.1", "10.0.0.2", "UDP", "5070", "6333")
        counter = Counter({"INVITE": 1, "200": 1})
        data = {link: {SIPCounter().dirBoth: counter}}

        c1 = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
            data=data,
        )

        self.assertEqual(c1.sip_filter, set(sip_filter))
        self.assertEqual(c1.host_filter, set(host_filter))
        self.assertEqual(c1.known_servers, set(known_servers))
        self.assertEqual(c1.known_ports, set(known_ports) | set(["5061", "5060"]))
        self.assertEqual(c1.name, name)
        self.assertEqual(c1.data, data)

    def test_add_sipmsg_without_msgdir_proto_ip_address_port(self):
        iterations = 1
        scenario_name = "simple"

        c = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        expected = expectations(scenario, iterations=iterations, msgdir=False)
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations}, initdir=initdir
        )
        for _, sipmsg, _, _, _, _, _, _ in sipgen:
            c.add(sipmsg)

        self.assertEqual(c.data, expected)

    def test_add_sipmsg_with_msgdir_without_ipaddr_port_proto(self):
        iterations = 1
        scenario_name = "simple"

        c = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        expected = expectations(scenario, iterations=iterations, msgdir=True)
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations}, initdir=initdir
        )
        for _, sipmsg, msgdir, _, _, _, _, _ in sipgen:
            c.add(sipmsg, msgdir)

        self.assertEqual(c._data, expected)

    def test_add_sipmsg_with_msgdir_from_client_only(self):
        iterations = 1
        scenario_name = "client_only"

        c = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        expected = expectations(scenario, iterations=iterations, msgdir=True)
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations}, initdir=initdir
        )
        for _, sipmsg, msgdir, _, _, _, _, _ in sipgen:
            c.add(sipmsg, msgdir)

        self.assertEqual(c.data, expected)

    def test_add_sipmsg_with_msgdir_ipaddr_without_proto(self):
        iterations = 1
        scenario_name = "simple"

        c = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5060"
        expected = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertEqual(c.data, expected)

    def test_add_sipmsg_with_msgdir_ipaddr_port_implicit_proto(self):
        iterations = 1
        scenario_name = "simple"
        proto = "TLS"

        c = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5060"
        expected = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertEqual(c.data, expected)

    def test_add_compact_sipmsg_with_msgdir_ipaddr_port_implicit_proto(self):
        iterations = 1
        scenario_name = "simple"
        proto = "TLS"

        c = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5060"
        expected = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
            compact=True,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertEqual(c.data, expected)

    def test_add_sipmsg_with_msgdir_ipaddr_port_explicit_proto(self):
        iterations = 1
        scenario_name = "simple"
        proto = "TLS"

        c = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5060"
        expected = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, proto in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertEqual(c.data, expected)

    def test_add_sipmsg_with_ipaddr_port_witout_msgdir_for_known_servers(self):
        iterations = 1
        scenario_name = "simple"
        proto = "TLS"
        known_servers = ["10.0.0.2"]

        c = SIPCounter(known_servers=known_servers)
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        client_ip, client_port = "10.0.0.1", "12345"
        server_ip, server_port = "10.0.0.2", "5060"
        expected = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, _, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, None, srcip, srcport, dstip, dstport)

        self.assertEqual(c.data, expected)

    def test_add_sipmsg_with_ipaddr_port_witout_msgdir_for_known_ports(self):
        iterations = 1
        scenario_name = "simple"
        proto = "TLS"
        known_ports = ["5070"]

        c = SIPCounter(known_ports=known_ports)
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        client_ip, client_port = "10.0.0.1", "1234"
        server_ip, server_port = "10.0.0.2", "5070"
        expected = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, _, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, None, srcip, srcport, dstip, dstport)

        self.assertEqual(c.data, expected)

    def test_add_sipmsg_without_cseq_method(self):
        iterations = 1
        scenario_name = "options"
        proto = "TLS"
        sip_filter = ["OPTIONS"]

        c = SIPCounter(sip_filter=sip_filter)
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        client_ip, client_port = "10.0.0.2", "12345"
        server_ip, server_port = "10.0.0.1", "5060"
        expected = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
            bad=True,
            leadinglines="\n\n\n\r",
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, proto in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport, proto)

        expected_without_resp = {}
        for k, v in expected.items():
            for k2, v2 in v.items():
                for k3, v3 in v2.items():
                    if not k3.isdigit():
                        (
                            expected_without_resp.setdefault(k, {})
                            .setdefault(k2, Counter())
                            .update({k3: v3})
                        )

        self.assertEqual(c.data, expected_without_resp)

    def test_update_c_with_c_should_return_k_which_is_2c(self):
        iterations = 1
        scenario_name = "shuffled"

        c = SIPCounter()
        k = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        expected = expectations(scenario, iterations=iterations, msgdir=False)
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations}, initdir=initdir
        )
        for _, sipmsg, _, _, _, _, _, _ in sipgen:
            c.add(sipmsg)

        iterations = 2
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations}, initdir=initdir
        )
        for _, sipmsg, _, _, _, _, _, _ in sipgen:
            k.add(sipmsg)

        c.update(expected)
        self.assertEqual(c.data, k.data)

    def test_subtract_k_which_is_c_from_2c_should_return_c(self):
        iterations = 1
        scenario_name = "shuffled"

        c = SIPCounter()
        k = SIPCounter()
        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        expected = expectations(scenario, iterations=iterations, msgdir=False)
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations}, initdir=initdir
        )
        for _, sipmsg, _, _, _, _, _, _ in sipgen:
            k.add(sipmsg)

        iterations = 2
        expected = expectations(scenario, iterations=iterations, msgdir=False)
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations}, initdir=initdir
        )
        for _, sipmsg, _, _, _, _, _, _ in sipgen:
            c.add(sipmsg)

        c.subtract(k)
        self.assertEqual(c._data, expected)

    def test_clear(self):
        iterations = 1
        scenario_name = "client_only"
        proto = "TCP"

        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5060"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"
        initdir = roledir[scenarios[scenario_name][0][1]]
        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )

        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, proto in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport, proto)

        c.clear()

        self.assertEqual(c._data, {})
        self.assertEqual(c.sip_filter, sip_filter)
        self.assertEqual(c.host_filter, host_filter)
        self.assertEqual(c.known_servers, known_servers)
        self.assertEqual(c.known_ports, (known_ports | set(["5060", "5061"])))
        self.assertEqual(c.name, name)

    def test__add__magic_method(self):
        iterations = 1
        proto = "TCP"

        scenario_name = "publish"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )
        expected1 = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        scenario_name = "notify"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter2 = set([x[0] for x in scenario])
        host_filter2 = set([client_ip])
        known_servers2 = set([server_ip])
        known_ports2 = set([server_port])
        name2 = "k"

        k = SIPCounter(
            sip_filter=sip_filter2,
            host_filter=host_filter2,
            known_servers=known_servers2,
            known_ports=known_ports2,
            name=name2,
        )
        expected2 = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, proto in sipgen:
            k.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        expected = merge_expectations(expected1, expected2)
        s = c + k

        self.assertEqual(s.data, expected)
        self.assertEqual(s.sip_filter, c.sip_filter)
        self.assertEqual(s.host_filter, c.host_filter)
        self.assertEqual(s.known_servers, c.known_servers)
        self.assertEqual(s.known_ports, c.known_ports | set(["5060", "5061"]))
        self.assertEqual(s.name, c.name)

    def test__iadd__magic_method(self):
        iterations = 1
        proto = "TCP"

        scenario_name = "publish"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )
        expected1 = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        scenario_name = "notify"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter2 = set([x[0] for x in scenario])
        host_filter2 = set([client_ip])
        known_servers2 = set([server_ip])
        known_ports2 = set([server_port])
        name2 = "k"

        k = SIPCounter(
            sip_filter=sip_filter2,
            host_filter=host_filter2,
            known_servers=known_servers2,
            known_ports=known_ports2,
            name=name2,
        )
        expected2 = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, proto in sipgen:
            k.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        expected = merge_expectations(expected1, expected2)
        c += k

        self.assertEqual(c.data, expected)
        self.assertEqual(c.sip_filter, sip_filter)
        self.assertEqual(c.host_filter, host_filter)
        self.assertEqual(c.known_servers, known_servers)
        self.assertEqual(c.known_ports, known_ports | set(["5060", "5061"]))
        self.assertEqual(c.name, name)

    def test__sub__magic_method_c_subtract_c_result_empty_data(self):
        iterations = 1
        proto = "TCP"

        scenario_name = "publish"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )
        expected1 = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        k = c
        k.name = "k"
        expected2 = expected1

        expected = merge_expectations(expected1, expected2, subtract=True)
        s = c - k

        self.assertEqual(s.data, expected)
        self.assertEqual(s.sip_filter, c.sip_filter)
        self.assertEqual(s.host_filter, c.host_filter)
        self.assertEqual(s.known_servers, c.known_servers)
        self.assertEqual(s.known_ports, c.known_ports)
        self.assertEqual(s.name, c.name)

    def test__isub__magic_method_same_link_diff_scenario_return_not_empty(self):
        iterations = 1
        proto = "TCP"

        scenario_name = "publish"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )
        expected1 = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        scenario_name = "notify"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter2 = set([x[0] for x in scenario])
        host_filter2 = set([client_ip])
        known_servers2 = set([server_ip])
        known_ports2 = set([server_port])
        name2 = "k"

        k = SIPCounter(
            sip_filter=sip_filter2,
            host_filter=host_filter2,
            known_servers=known_servers2,
            known_ports=known_ports2,
            name=name2,
        )
        expected2 = expectations(
            scenario,
            iterations=iterations,
            msgdir=True,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            proto=proto,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, proto in sipgen:
            k.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        expected = merge_expectations(expected1, expected2, subtract=True)
        c -= k

        self.assertEqual(c.data, expected)
        self.assertEqual(c.sip_filter, sip_filter)
        self.assertEqual(c.host_filter, host_filter)
        self.assertEqual(c.known_servers, known_servers)
        self.assertEqual(c.known_ports, known_ports | set(["5060", "5061"]))
        self.assertEqual(c.name, name)

    def test_contains_ipaddr_port_or_sip_msgtype(self):
        iterations = 1
        proto = "TCP"

        scenario_name = "transferred"
        client_ip, client_port = "10.0.0.2", "1234"
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertTrue(client_ip in c)
        self.assertTrue(server_port in c)
        self.assertTrue("REFER" in c)
        self.assertFalse("2345" in c)
        self.assertFalse("10.0.0.3" in c)
        self.assertFalse("MESSAGE" in c)

    def test_total(self):
        iterations = 10
        proto = "TLS"

        scenario_name = "canceled"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )
        expected = len(scenario) * iterations
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertEqual(c.total, expected)

    def test__lt__gt__ne__le__ge__magic_methods(self):
        iterations = 1
        proto = "TLS"

        scenario_name = "simple"
        client_ip, client_port = randipport()
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        iterations = 2
        k = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
        )
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            k.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertTrue(c < k)
        self.assertTrue(k > c)
        self.assertTrue(k != c)
        self.assertTrue(c <= c)
        self.assertTrue(k >= k)

    def test_elements(self):
        iterations = 1
        proto = "TCP"

        scenario_name = "shuffled"
        client_ip, client_port = "10.0.0.2", "1234"
        server_ip, server_port = "10.0.0.1", "5070"

        scenario = scenarios[scenario_name]
        initdir = roledir[scenario[0][1]]
        sip_filter = set([x[0] for x in scenario])
        host_filter = set([client_ip])
        known_servers = set([server_ip])
        known_ports = set([server_port])
        name = "c"

        c = SIPCounter(
            sip_filter=sip_filter,
            host_filter=host_filter,
            known_servers=known_servers,
            known_ports=known_ports,
            name=name,
        )
        expected = set(x[0] for x in scenario)
        sipgen = sip_generator(
            scenario_iterations={scenario_name: iterations},
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            initdir=initdir,
            proto=proto,
        )
        for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
            c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        self.assertEqual(set(c.elements()), expected)

    def test_summary(self):
        iterations = 1
        proto = "UDP"
        test_scenarios = ["canceled", "transferred", "global_error", "moved"]
        server_ip, server_port = "10.0.0.1", "5070"

        known_servers = set([server_ip])
        known_ports = set([server_port])
        c = SIPCounter(known_servers=known_servers, known_ports=known_ports)
        expecteds = []

        for scenario_name in test_scenarios:
            scenario = scenarios[scenario_name]
            initdir = roledir[scenario[0][1]]
            client_ip, client_port = randipport()

            expected = expectations(
                scenario,
                iterations=iterations,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                proto=proto,
                msgdir=True,
            )
            expecteds.append(expected)

            sipgen = sip_generator(
                scenario_iterations={scenario_name: iterations},
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                initdir=initdir,
                proto=proto,
            )
            for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
                c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        expected = {("SUMMARY",): {}}
        for e in expecteds:
            for v in e.values():
                for msgdir, counter in v.items():
                    expected[("SUMMARY",)].setdefault(msgdir, Counter()).update(counter)

        self.assertEqual(c.summary(), expected)

    def test_most_common(self):
        iterations = 1
        proto = "UDP"
        depth = 3
        n = 2

        test_scenarios = ["simple", "shuffled", "transferred"]
        server_ip, server_port = "10.0.0.1", "5070"

        known_servers = set([server_ip])
        known_ports = set([server_port])
        c = SIPCounter(known_servers=known_servers, known_ports=known_ports)
        expecteds = {}

        for scenario_name in test_scenarios:
            scenario = scenarios[scenario_name]
            initdir = roledir[scenario[0][1]]
            client_ip, client_port = randipport()

            expected = expectations(
                scenario,
                iterations=iterations,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                proto=proto,
                msgdir=True,
            )
            expecteds[scenario_name] = expected

            sipgen = sip_generator(
                scenario_iterations={scenario_name: iterations},
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                initdir=initdir,
                proto=proto,
            )
            for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
                c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        scenario_names_by_msgcount = sorted(
            test_scenarios, reverse=True, key=lambda x: len(scenarios[x])
        )
        expected = OrderedDict()
        for scenario_name in scenario_names_by_msgcount[:n]:
            for k, v in expecteds[scenario_name].items():
                expected[k[:depth]] = v

        self.assertEqual(c.most_common(n=n, depth=depth), expected)

    def test_groupby(self):
        iterations = 1
        proto = "TCP"
        depth = 3

        test_scenarios = ["simple", "shuffled", "transferred"]
        server_ip, server_port = "10.0.0.1", "5080"

        c = SIPCounter(known_servers=set(["10.0.0.2"]))
        expecteds = []

        for scenario_name in test_scenarios:
            scenario = scenarios[scenario_name]
            initdir = roledir[scenario[0][1]]
            client_ip, client_port = "10.0.0.2", randipport()[1]

            expected = expectations(
                scenario,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                msgdir=True,
                proto=proto,
                iterations=iterations,
            )
            expecteds.append(expected)

            sipgen = sip_generator(
                scenario_iterations={scenario_name: iterations},
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                initdir=initdir,
                proto=proto,
            )
            for _, sipmsg, msgdir, srcip, srcport, dstip, dstport, _ in sipgen:
                c.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)

        merge = partial(merge_expectations, depth=depth)
        expected = reduce(merge, expecteds)

        self.assertEqual(c.groupby(depth=depth), expected)

    def test_compact(self):
        proto = "TCP"
        client_ip, client_port = randipport()
        server_ip, server_port = randipport()
        c = SIPCounter()
        data = {
            (server_ip, client_ip, proto, server_port, client_port): {
                c.dirIn: Counter({"INVITE": 0}),
                c.dirOut: Counter({"200": -1}),
            }
        }
        c.update(data)
        c.compact()

        self.assertEqual(c.data, {})


if __name__ == "__main__":
    unittest.main()
