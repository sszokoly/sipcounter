# -*- coding: utf-8 -*-
"""SIPCounter: counts SIP messages."""

from __future__ import print_function
from collections import Counter, OrderedDict
from copy import deepcopy
import csv
import pickle
import sys

__version__ = "0.0.1"


class SIPMessage(object):
    """Simple SIP message object to retrieve message body properties,
    headers easily and to provide a way to extend functionality in
    the future.
    """
    def __init__(self, body):
        self._str = str(body).lstrip()

    @property
    def size(self):
        """int: returns the size of the message"""
        return len(self._str)

    def request(self):
        """str: retrieves request type."""
        if self.is_request():
            space = self._str.find(" ")
            if space >= 0:
                req = self._str[0:space]
                if req == "INVITE" and self.is_indialog_request():
                    req = "ReINVITE"
                return req
        return "UNKNOWN"

    def response(self):
        """str: retrieves response type."""
        if self.is_response():
            start = self._str.find(" ") + 1
            if start >= 1:
                end = self._str.find(" ", start)
                if end == -1:
                    end = self._str.find("\n")
                if end > start:
                    return self._str[start:end]
        return "UNKNOWN"

    def method(self):
        """str: retrieves method type from CSeq header."""
        hdr = self.header("CSeq")
        if hdr:
            start = hdr.find(" ")
            if start >= 0:
                return hdr[start+1:].rstrip()
            elif self.is_request():
                return self.request()
        return "UNKNOWN"

    def protocol(self):
        """str: retrieves protocol type from top Via header."""
        hdr = self.header("Via")
        if not hdr:
            hdr = self.header("v")
        if hdr:
            start = hdr.find('/2.0/')
            if start >= 1:
                end = hdr.find(' ', start)
                return hdr[start+5:end]
        return "UDP"

    def header(self, header_name):
        """Retrieves the requested header.

        Args:
            header_name (str): header name without ":" to be retrieved

        Returns:
            str: requested header line
        """
        start = self._str.find(header_name + ':')
        if start == -1:
            return None
        end = self._str.find("\n", start)
        if end == -1:
            end = self.size
        return self._str[start+len(header_name)+1:end].strip()

    def header_param(self, header_name, param):
        """Retrieves a specific parameter from the requested header.

        Args:
            header_name (str): header name without ":"
            param (str): parameter name to retrieve from header

        Returns:
            str: parameter
        """
        hdr = self.header(header_name)
        if hdr is not None:
            start = hdr.find(param)
            if start > -1:
                start += len(param)
                if hdr[start] == '=':
                    start += 1
                end = hdr.find(';', start)
                if end == -1:
                    end = len(hdr)
                if end > 0:
                    return hdr[start:end]
        return None

    def is_indialog_request(self):
        """bool, None: if message has "tag" paramater in the "To" header."""
        return None if not self.size else (
                self.header_param("To", "tag") is not None or
                self.header_param("t", "tag") is not None)

    def is_response(self):
        """bool, None: if message is a response."""
        return None if not self.size else (
               self._str.startswith(("SIP/2.0", "sip/2.0")))

    def is_request(self):
        """bool, None: if message is a request."""
        return None if not self.size else (
               not self.is_response())

    def __contains__(self, item):
        return item in self._str

    def __len__(self):
        return self.size

    def __str__(self):
        return self._str


class SIPCounter(object):
    """Implements a simple, stateless SIP message counter with optional
    message direction, IP address, transport protocol and port tracking.
    It can also filter and count messages of certain request or response
    types only or count messages from certain hosts. A link is comprised
    of the IP addresses of communicating hosts, the transport protocol type
    (TLS, TCP, UDP), which can also be inferred from the SIP message body,
    and the ports. in the absence of these optional arguments a link
    is designated by "local" and "remote" hosts. The internal self._data
    OrderedDict stores the message counts for each link in the following
    fashion:

    OrderedDict([((server_ip, client_ip, protocol, server_port, client_port),
                    {<dirIn>:  Counter({<msgtype>: int}), 
                     <dirOut>: Counter({<msgtype>: int})}),
     ...)]

    Or more specifically:

    OrderedDict([(("10.1.1.1", "10.1.1.2", "TCP", "5060", "12345"):
                    {"->": Counter({"INVITE": 1}), 
                     "<-": Counter({"100": 1, "180": 1})}),
     ...)]

    Attributes:
        dirIn (str): respresentation of directionality for inbound messages,
            by default "<-"
        dirOut (str): respresentation of directionality for outbound messages,
            by default "->"
        dirBoth (str): respresentation of directonality for any direction,
            by default "<>", used when the direction of the message cannot
            be determined nor is provided
        local_name (str): respresentation of "server" (left) side when
            the host IP address is not provided, by default "local"
        remote_name (str): respresentation of "client" (right) side when
            the host IP address is not provided, by default "remote"
        _data (dict): stores link information and corresponding message
            counts for In, Out or Both directions for each link
        ORDER (dict(str:int)): maps message types to column positions
            when converting self._data to a string.
    """
    ORDER = {
        "INVITE": 0,
        "ReINVITE": 1,
        "UPDATE": 2,
        "CANCEL": 3,
        "PRACK": 4,
        "BYE": 5,
        "ACK": 6,
        "SUBSCRIBE": 7,
        "NOTIFY": 8,
        "PUBLISH": 9,
        "REFER": 10,
        "OPTIONS": 11,
        "INFO": 12,
        "REGISTER": 13,
        "MESSAGE": 14,
        "PING": 15,
        "UNKNOWN": 16,
    }

    DEPTH_ERR = "depth should be an integer from 1 to 5."
    TYPEMISMADD_ERR = "can only add SIPCounter to a SIPCounter."
    TYPEMISMSUB_ERR = "can only subtract SIPCounter from a SIPCounter."
    TYPEMISMDIR_ERR = "SIPCounter type mismatch."

    def __init__(self, **kwargs):
        """Initializes a SIPCounter instance.

        Args:
            sip_filter (list(str)): a collection of SIP message types
                of interest to count. For example to count only INVITE
                (incl. ReINVITE) requests and any error responses of
                INVITE dialogs:

                    c = SIPCounter(sip_filter=["INVITE", "4", "5", "6"])

                Or to be more specific (all 40x and only 503 errors).

                    c = SIPCounter(sip_filter=["INVITE", "40", "503"])

            host_filter (list(str)): a collection of IP addresses so as
                to count only messages sent or received by these hosts.
                For example:

                    c = SIPCounter(host_filter=["10.1.1.1", "10.1.1.2"])

            host_exclude (list(str)): a collection of host IP addresses
                so as to not count messages sent or received by these hosts.
                It should not be used together with "host_filter".
                For example:

                c = SIPCounter(host_exclude=["10.1.1.3", "10.1.1.4"])

            known_servers (list(str)): a collection of host IP addesses
                known to be SIP servers, proxies or other SIP UA which
                are to be considered the "server" side of a link. If not
                provided the internal logic tries to guess the server
                (or "local") and client (or "remote") side from other
                information based on the received parameters. See self.add
                for more info. For example:

                c = SIPCounter(known_servers=["10.1.1.1", "10.1.1.2"])

            known_ports (list(str)): a collection of port numbers known
                to be used by SIP servers, proxies, in addition to the
                well-known SIP port 5060 and 5061. For example:

                c = SIPCounter(known_ports=["5070", "5080"])

            data (dict(tuple(str): dict)): a self._data like dictionary used
                to initialize a SIPCounter instance with some prepopulated
                links and corresponding Counters. For example:

                c = SIPCounter(data=
                        OrderedDict([((
                            "<server ip>",
                            "<client ip>",
                            "<protocol>",
                            "<server_port>",
                            "<client port>"
                        ):
                            {"dirIn": Counter(
                                                {
                                                    "<msgtypeA>" : int,
                                                    "<msgtypeB>" : int,
                                                }
                                            ),
                             "dirOut": Counter(
                                                {
                                                    "<msgtypeC>" : int,
                                                    "<msgtypeD>" : int,
                                                }
                                            )
                            },
                        )])

                    Or more specifically:

                    data=OrderedDict([(("10.1.1.1", "10.1.1.2", "TCP", "5060", "12345"):
                                        {"->": Counter({"INVITE": 1, "BYE": 1, "ACK": 1}),
                                         "<-": Counter({"100": 1, "180": 1, "200": 2})})])

                    c = SIPCounter(data=data)

            name (str): the name of the class instance. For example:

                c = SIPCounter(name="SBC Cone-A INVITE only",
                               sip_filter=["INVITE", "2", "3", "4", "5", "6"])

            greedy (bool): to count all response messages of the requests provided
                in the sip_filter implicitely unless a reponse message type is
                also given in the sip_filter explicitely.

        Returns:
            obj (SIPCounter): a SIPCounter class instance.
        """
        self.dirIn = "<-"
        self.dirOut = "->"
        self.dirBoth = "<>"
        self.local_name = "local"
        self.remote_name = "remote"
        self.name = str(kwargs.get("name", ""))
        self.greedy = kwargs.get("greedy", True)
        self._data = kwargs.get("data", OrderedDict())
        self.sip_filter = set(kwargs.get("sip_filter", []))
        self.host_filter = set(kwargs.get("host_filter", []))
        self.host_exclude = set(kwargs.get("host_exclude", []))
        self.known_servers = set(kwargs.get("known_servers", []))
        self.known_ports = set(int(x) for x in kwargs.get("known_ports", [])) | set([5060, 5061])
        self.response_filter = tuple(x for x in self.sip_filter if x.isdigit())
        self.request_filter = set(x for x in self.sip_filter if not x.isdigit())

        if "INVITE" in self.request_filter:
            self.request_filter.add("ReINVITE")

    @property
    def data(self):
        """dict: getter method for self._data."""
        return self._data

    @property
    def total(self):
        """int: total sum of all Counter values in self._data."""
        return self.sum()

    @staticmethod
    def _joinlink(link, width=47, sep="-"):
        """Concatenates link tuple values to a string depending on the
        number of values in the tuple. For example 5-value link as this:

        (server_ip, client_ip, proto, server_port, client_port)

        is returned as:

        "server_ip<sep>proto<sep>server_port<sep>client_port<sep>client_ip "

        left justitifed to "width". With less values in the tuple:

        "server_ip<sep>proto<sep>server_port<sep>client_ip                 "
        "server_ip<sep>proto<sep>client_ip                                 "
        "server_ip<sep>client_ip                                           "
        "server_ip                                                         "

        Args:
            link (tuple(str)): tuple of 5 or less string values
                containing the server and client IP, transport protocol,
                server and client side port numbers
            width (int, optional): width of the resulting string
            sep (str, optional): separator string

        Returns:
            str: concatenated values of link tuple separated by sep.
        """
        seq = [0]
        if 2 <= len(link) <= 5:
            seq += list(range(-(len(link) - 2), 0)) + [1]
        return sep.join(str(link[i]) for i in seq if str(link[i])).ljust(width)

    def msgdirs(self, data=None):
        """Returns the expected labels of message directions so as to know
        if the instance of this class is direction aware or not.
        For example if the message direction is not provided the returned
        tuple is:

        ("<>",)

        otherise:

        ("->", "<-")

        Args:
            data (odict, optional): self._data like OrderedDict

        Returns:
            tuple: direction labels expected to be seen in self._data
        """
        if data is None:
            data = self._data

        if not data:
            return ()

        found = set(next(iter(data.values())).keys())
        if set([self.dirOut, self.dirIn]) & found:
            return (self.dirOut, self.dirIn)
        elif set([self.dirBoth]) & found:
            return (self.dirBoth,)
        return tuple(found)

    def _makelink(self, msgdir=None, srcip=None, srcport=None,
                 dstip=None, dstport=None, proto=None):
        """Builds the link tuple of 5 values from the supplied arguments
        by determining the server/client sides. The resulting tuple serves
        as the key in self._data and is built as follows:

        (server_ip, client_ip, proto, server_port, client_port)

        If srcip, srcport, dstip, dstport are not provided the resulting
        link will be in the following format:

        (self.local_name, self.remote_name, proto, "", "")

        or more specifically by default:

        ("local", "remote", "UDP", "", "")

        Args:
            msgdir (str, optional): message direction, "IN" or "OUT"
            srcip (str, optional): source IP address
            srcport (int, optional): source SIP port
            dstip (str, optional): destination IP address
            dstport (int, optional): destination SIP port
            proto (str, optional): protocol type, "TCP" or "TLS" or "UDP"

        Returns:
            tuple: of a tuple of 5 values (link) and a string (keystr)
        """
        if msgdir is not None and msgdir.upper() == "IN":
            keystr = self.dirIn
        elif msgdir is not None and msgdir.upper() == "OUT":
            keystr = self.dirOut
        elif srcip and dstip and srcport and dstport:
            # Just in case
            srcport = int(srcport)
            dstport = int(dstport)
            if self.known_servers:
                if srcip in self.known_servers:
                    keystr = self.dirOut
                elif dstip in self.known_servers:
                    keystr = self.dirIn
            else:
                if dstport in self.known_ports:
                    keystr = self.dirIn
                elif srcport in self.known_ports:
                    keystr = self.dirOut
                elif srcport > dstport:
                    keystr = self.dirIn
                elif srcport < dstport:
                    keystr = self.dirOut
                else:
                    keystr = self.dirIn
        else:
            keystr = self.dirBoth

        if keystr == self.dirOut:
            server_ip = srcip or self.local_name
            server_port = (srcport if srcport else "")
            client_ip = dstip or self.remote_name
            client_port = (dstport if dstport else "")
        else:
            server_ip = dstip or self.local_name
            server_port = (dstport if dstport else "")
            client_ip = srcip or self.remote_name
            client_port = (srcport if srcport else "")

        proto = proto or ""
        link = (server_ip, client_ip, proto, server_port, client_port)
        return link, keystr

    def _gettype(self, sipmsg=None, msgtype=None, method=None, proto=None):
        """Retrieves the msgtype, method and proto from the supplied arguments.
        If sipmsg is provided it will use that to extract the returned values.
        Otherwise it will pass the msgtype and method back to the caller.

        Args:
            sipmsg (str, optional): SIP message body
            msgtype (str, optional): message type if sipmsg is not provided
            method (str, optional): method type if sipmsg is not provided
            proto (str, optional): protocol type, "TCP" or "TLS" or "UDP"

        Returns:
            tuple: a tuple of 3 string values: msgtype, method, proto
        """
        if sipmsg:
            sipmsg = SIPMessage(sipmsg)
            method = sipmsg.method()
            proto = sipmsg.protocol().upper()
            if sipmsg.is_response():
                msgtype = sipmsg.response()
            else:
                msgtype = sipmsg.request()

        elif not method and not msgtype:
            method = "UNKNOWN"
            msgtype = "UNKNOWN"

        proto = proto or "UDP"
        return msgtype, method, proto

    def is_host_ignorable(self, srcip, dstip):
        """Determines whether the SIP message should be discarded
        based on the values of self.host_filter or self.host_exclude.

        Args:
            srcip (str): source IP address
            dstip (str): destination IP address

        Returns:
            bool: True=ignore, False=do not ignore
        """
        if self.host_filter:
            if (srcip not in self.host_filter and
                dstip not in self.host_filter):
                return True

        if self.host_exclude:
            if (srcip in self.host_exclude or
                dstip in self.host_exclude):
                return True
        return False

    def is_sipmsg_ignorable(self, msgtype, method):
        """Determines whether the SIP message should be discarded
        based on the values of self.sip_filter and self.greedy.

        Args:
            msgtype (str): SIP request or response type
            method (str): SIP method type (method in CSeq header)

        Returns:
            bool: True=ignore, False=do not ignore
        """
        if not msgtype and not method:
            return True

        # Allow implicit responses only or all if filter is empty
        if (self.greedy and msgtype[0].isdigit() and
           (not self.request_filter or method in self.request_filter) and
           (not self.response_filter or msgtype.startswith(self.response_filter))):
            return False

        # Allow explicit responses only or all if filter is empty
        if (not self.greedy and msgtype[0].isdigit() and
        ((self.response_filter and msgtype.startswith(self.response_filter) and
         (not self.request_filter or method in self.request_filter)) or
         (not self.request_filter and not self.response_filter))):
            return False

        # Allow explicit requests only or all if filter is empty
        if (not msgtype[0].isdigit() and
           ((self.request_filter and method in self.request_filter) or
            (not self.response_filter and not self.request_filter))):
            return False

        return True

    def add(self, sipmsg=None, msgdir=None, srcip=None, srcport=None,
            dstip=None, dstport=None, proto=None, msgtype=None, method=None):
        """Increments the Counters in self._data according to SIP message type
        and filters.

        Args:
            sipmsg (str, optional): SIP message body
            msgdir (str, optional): message direction, "IN" or "OUT"
            srcip (str, optional): source IP address
            srcport (int, optional): source SIP port
            dstip (str, optional): destination IP address
            dstport (int, optional): destination SIP port
            proto (str, optional): protocol type, "TCP" or "TLS" or "UDP"
            msgtype (str, optional): message type if sipmsg is not provided
            method (str, optional): method type if sipmsg is not provided

        Returns:
            int: 1 if message was added to self._data or 0 otherwise
        """
        if self.is_host_ignorable(srcip, dstip):
            return 0

        msgtype, method, proto = self._gettype(sipmsg, msgtype, method, proto)
        if self.is_sipmsg_ignorable(msgtype, method):
            return 0

        link, keystr = self._makelink(msgdir, srcip, srcport, dstip, dstport, proto)
        (self._data.setdefault(link, {})
                   .setdefault(keystr, Counter())
                   .update([msgtype]))
        return 1

    def update(self, data):
        """Updates self._data with values of data argument. As opposed
        to the 'add' method which adds SIP messages one by one 'update'
        adds multiple links and corresponding values to self._data.

        Note:
            The primary purpose of this method is to populate the
            the values of the internal Counters directly with multiple
            values at once. To subtract multiple values from the
            Counters use the 'subtract' method.

        Args:
            data (odict): a self._data like OrderedDict. For example:

            c = SIPCounter()
            data = OrderedDict([(("1.1.1.1", "2.2.2.2", "tcp", "5060", "34556"),
                                    {"<-": Counter({"UPDATE": 1, "ReINVITE": 1}),
                                     "->": Counter({"200": 1, "100": 1})})])
            c.update(data)
        """
        if isinstance(data, dict):
            for k, v in data.items():
                for k2, v2 in v.items():
                    (self._data.setdefault(k, {})
                         .setdefault(k2, Counter())
                         .update(v2))

    def subtract(self, data, compact=True):
        """Updates self._data with values of data argument but it
        subtracts the values from the internal Counters of self._data.

        Note:
            This is unlikely to be used often directly. It's primary
            purpose is to allow subtraction of a SIPCounter instance from
            another SIPCounter instance using "-" or "-=" operators.

        Args:
            data (odict): a self._data like OrderedDict
            compact (bool, optional): to compact self._data also
        """
        if isinstance(data, OrderedDict):
            for k, v in data.items():
                for k2, v2 in v.items():
                    if k in self._data and k2 in self._data[k]:
                        subset = {
                                    k3: v3 for k3, v3 in v2.items()
                                    if k3 in self._data[k][k2]
                                }
                        self._data[k][k2].subtract(subset)
            if compact:
                self.compact()

    def clear(self):
        """Clears self._data."""
        self._data.clear()

    def compact(self):
        """Compacts self._data by removing message types with values of
        zero or less. Links having all of their Counter values with values
        zero or less will be removed completely as well.
        """
        compacted = OrderedDict()
        for k, v in self._data.items():
            for k2, v2 in v.items():
                for k3, v3 in v2.items():
                    if v3 > 0:
                        (
                            compacted.setdefault(k, {})
                            .setdefault(k2, Counter())
                            .update({k3: v3})
                        )
        self._data = compacted

    def items(self):
        """iterator: returns the items of self._data."""
        return self._data.items()

    def keys(self):
        """iterator: returns keys (aka links) of self._data."""
        return self._data.keys()

    def links(self):
        """iterator: same as keys() method."""
        return self.keys()

    def values(self):
        """iterator: returns the values of self._data."""
        return self._data.values()

    def msgtypes(self, data=None):
        """Returns a list of SIP message types found in self._data
        ordered according to the values of self.ORDER.

        Args:
            data (odict, optional): a self._data like OrderedDict

        Returns:
            list(str): ordered unique message types
        """
        if data is None:
            data = self._data

        m = set(k for d in data.values() for v in d.values() for k in v)
        requests = sorted(
                            (x for x in m if not x.isdigit()),
                            key=lambda x: self.ORDER.get(x, len(self.ORDER)),
                        )
        responses = sorted((x for x in m if x.isdigit()))
        return requests + responses

    def groupby(self, depth=4, data=None):

        """Groups (merges) links based on the number (depth) of items
        considered significant in the link tuples. Also sorts the result
        by link elements in the following order of importance:

        server_ip, proto, server_port, client_port, client_ip

        For example if self._data is:

        OrderedDict([(
         ("1.1.1.1", "2.2.2.2", "TCP", "5060", "33332"),  {"<-": Counter({"INVITE": 1})}),
         ("1.1.1.1", "2.2.2.2", "TCP", "5060", "33333"),  {"<-": Counter({"INVITE": 1})}),
         ("1.1.1.1", "3.3.3.3", "TCP", "5060", "33334"),  {"<-": Counter({"INVITE": 1})}),
         ("1.1.1.1", "2.2.2.2", "TCP", "5062", "33335"),  {"<-": Counter({"INVITE": 1})}),
         ("1.1.1.1", "2.2.2.2", "TCP", "5061", "33336"),  {"<-": Counter({"INVITE": 1})})])

        Calling groupby(depth=5) would only sort the links and return an
        OrderedDict placing link with ("1.1.1.1", "2.2.2.2",...) before
        ("1.1.1.1", "3.3.3.3"...).

        Calling groupby(depth=4), default, would not only sort by link
        values but also merge the Counters of all the links with key
        containing ("1.1.1.1", "2.2.2.2", "TCP", "5060", ...) ignoring
        the client port.

        OrderedDict([(
         ("1.1.1.1", "2.2.2.2", "TCP", "5060"),  {"<-": Counter({"INVITE": 2})}),
         ("1.1.1.1", "2.2.2.2", "TCP", "5062"),  {"<-": Counter({"INVITE": 1})}),
         ("1.1.1.1", "2.2.2.2", "TLS", "5061"),  {"<-": Counter({"INVITE": 1})}),
         ("1.1.1.1", "3.3.3.3", "TCP", "5060"),  {"<-": Counter({"INVITE": 1})})])

        Calling groupby(depth=3) would merge and order the link ignoring
        both the server and client side ports:

        OrderedDict([(
         ("1.1.1.1", "2.2.2.2", "TCP"), {"<-": Counter({"INVITE": 3})}),
         ("1.1.1.1", "2.2.2.2", "TLS"), {"<-": Counter({"INVITE": 1})}),
         ("1.1.1.1", "3.3.3.3", "TCP"), {"<-": Counter({"INVITE": 1})})]),

        Calling groupby(depth=2) would merge and order even further:

        OrderedDict([(
         ("1.1.1.1", "2.2.2.2"), {"<-": Counter({"INVITE": 4})}),
         ("1.1.1.1", "3.3.3.3"), {"<-": Counter({"INVITE": 1})})])

        Args:
            depth (int): number of values from the key tuple which are
                considered significant during grouping.
            data (odict, optional): a self._data like OrderedDict

        Returns:
            dict: OrderedDict of grouped links

        Raises:
            ValueError: if depth is not a number from 1 to 5
        """
        if depth not in (1, 2, 3, 4, 5):
            raise ValueError(self.DEPTH_ERR)

        if data is None:
            data = self._data

        d = {}
        for link, v in data.items():
            for msgdir, counter in v.items():
                (
                    d.setdefault(link[0:depth], {})
                     .setdefault(msgdir, Counter())
                     .update(counter)
                )
        getter = lambda x: tuple(x[i] for i in (0, 2, 3, 4, 1) if len(x) > i)
        ordered = sorted(d.keys(), key=getter, reverse=False)

        return OrderedDict((k, d[k]) for k in ordered)

    def most_common(self, n=None, depth=4, data=None):
        """Orders self._data based on the sum of Counter values per link
        and returns the "n" busiest links in descending order. Optionally
        it groups (merges) links too.

        Args:
            n (int, optional): number of busiest links to return, if not
                provided it returns all links ordered by total number of
                messages.
            depth (int, optional): depth of significance during grouping,
                with default value 4, merging links of same clients
                regardless of client side port.
            data (odict, optional): a self._data like OrderedDict

        Returns:
            odict: OrderedDict of top "n" links with highest sum
                of message count

        Raises:
            ValueError: if depth is not a number from 1 to 5
        """
        if depth not in (1, 2, 3, 4, 5):
            raise ValueError(self.DEPTH_ERR)

        if data is None:
            data = self._data

        data = self.groupby(depth=depth)
        maxes = self.sum(axis=0, data=data)
        idx = sorted(list(zip(maxes, range(len(maxes)))), reverse=True)
        items = list(data.items())
        if n is not None:
            idx = idx[0:n]

        return OrderedDict(items[i[1]] for i in idx)

    def sum(self, axis=None, data=None):
        """Sum of link Counters over a given axis.

        axis=0 operates horizontally across the Counters of a link
        axis=1 operates downwards, across message types for each direction
        axis=None sums all the Counters in self._data

        Note:
            This method returns a list because self._data or optional
            data argument is an OrderedDict and so the order of values
            is the same as the order of links.

        Args:
            axis (int, optional): axis along which the sum is calculated,
                possible values 0, 1 or None
            data (dict, optional): a self._data like OrderedDict

        Returns:
            int, list(int): if axis is None an integer, otherwise a list
        """
        if data is None:
            data = self._data

        cols = self.tocolumns(data)
        if axis == 0 or axis == "index":
            return [sum(v) for v in cols.values()]
        elif axis == 1 or axis == "columns":
            return [sum(v) for v in zip(*cols.values())]
        return sum(sum(v) for v in zip(*cols.values()))

    def max(self, axis=None, data=None):
        """Returns the maximum over a given axis.

        axis=0 operates horizontally across the Counters of a link
        axis=1 operates downwards, across message types for each direction
        axis=None finds maximum across all the Counters in self._data

        Note:
            This method returns a list because self._data or optional
            data argument is an OrderedDict and so the order of values
            is the same as the order of links.

        Args:
            axis (int, optional): axis along which the max is located,
                possible values 0, 1 or None
            data (dict, optional): a self._data like OrderedDict

        Returns:
            int, list(int): if axis is None an integer, otherwise a list
        """
        if data is None:
            data = self._data

        cols = self.tocolumns(data)
        if axis == 0 or axis == "index":
            return [max(v) for v in cols.values()]
        elif axis == 1 or axis == "columns":
            return [max(v) for v in zip(*cols.values())]
        return max(count for v in cols.values() for count in v)

    def tocolumns(self, data=None):
        """Transforms link Counters to a list of Counter values for
        each possible message type and direction. For example for a
        grouped (depth=4, without client port) data like this:

        OrderedDict([(
         ("10.1.1.1", "10.1.1.2", "TCP", "5060"):  {"->": Counter({"BYE": 1})}),
         ("10.1.1.1", "10.1.1.3", "TCP", "5060"):  {"<-": Counter({"200": 1})})])

        or more descriptively
                                                    BYE  BYE  200  200
                                                    OUT   IN  OUT   IN
        ("10.1.1.1", "10.1.1.2", "TCP", "5060")       1    0    0    0
        ("10.1.1.1", "10.1.1.3", "TCP", "5060")       0    0    0    1

        would return the following dict:

        {("10.1.1.1", "10.1.1.2", "TCP", "5060"): [1, 0, 0, 0],
         ("10.1.1.1", "10.1.1.3", "TCP", "5060"): [0, 0, 0, 1],
        }

        Args:
            data (odict, optional): self._data like ordered dictionary

        Returns:
            dict: with links as keys and list if integers as values
            each corresponding to a possible combination of message
            type and direction and Counter value for that combination.
        """
        if data is None:
            data = self._data

        cols = OrderedDict()
        msgdirs = self.msgdirs()
        msgtypes = self.msgtypes()

        for link, v in data.items():
            for m in msgtypes:
                for d in msgdirs:
                    cols.setdefault(link, []).append(v.get(d, {}).get(m, 0))
        return cols

    def tostring(self, depth=4, title="", sep="-", name=True, header=True,
                 links=True, summary=True, sortby_total=False, link_margin=1,
                 zeros=True, data=None):
        """Converts self._data to a tabulated string for pretty printing.

        Args:
            depth (int, optional): indicating how deep into the key
                to look into when grouping the links, values 1 to 5
            title (str, optional): extra information to print inline
                with top line, for example a timestamp, location, etc
            sep (str, optional): separator between IP, protocol and port
            name (bool, optional): to include SIPCounter name
            header (bool, optional): to include header
            links (bool, optional): to include links
            summary (bool, optional): to include horizonal/vertical summary
            sortby_total (bool, optional): to sort by sum of link Counters
            link_margin (int, optional): number of spaces between the links
                and the first SIP message column
            zeros (bool, optional): show 0 counts instead of blanks
            data (odict, optional): self._data like OrderedDict

        Returns:
            str: tabulated string representation of self._data

        Raises:
            ValueError: if depth is not a number from 1 to 5
        """
        if depth not in (1, 2, 3, 4, 5):
            raise ValueError(self.DEPTH_ERR)

        if data is None:
            if sortby_total:
                data = self.most_common(depth=depth)
            else:
                data = self.groupby(depth=depth)

        if not data:
            return ""

        out = []
        msgdirs = self.msgdirs(data=data)
        msgtypes = self.msgtypes(data=data)
        nofdirs = len(msgdirs)
        zero = 0 if zeros else ""

        longestnum = len(str(self.sum(data=data)))
        longestmsg = max(len(x) for x in msgtypes)
        longestlnk = max(len(sep.join(str(x) for x in k)) for k in data.keys())
        longestcol = max(longestnum * nofdirs, longestmsg)

        column_width = int(round(longestcol / float(nofdirs)) * nofdirs) + 1
        link_width = (max(longestlnk * int(links), len(title), len(self.name))
                      + link_margin)

        if header:
            counter_name = self.name if name else ""
            o = [counter_name.ljust(link_width)]
            o.extend([elem.center(column_width) for elem in msgtypes])
            out.append(o)

            o = [title.ljust(link_width)]
            for _ in msgtypes:
                for i in range(nofdirs):
                    o.append("".join((msgdirs[i][0],
                                      (column_width // nofdirs - 2) * "-",
                                      msgdirs[i][1:])))
            out.append(o)

        if links:
            for link, cols in self.tocolumns(data).items():
                o = [self._joinlink(link, width=link_width, sep=sep)]
                for col in cols:
                    col = (zero if col == 0 else col)
                    o.append((str(col).rjust(column_width // nofdirs)))
                out.append(o)

        if summary:
            total = self.sum(data=data)
            linksum_width = max(len("TOTAL"), len(str(total)))
            out[0].append("TOTAL".rjust(linksum_width))
            if links:
                for i, linktotal in enumerate(self.sum(0, data), start=2):
                    linktotal = (zero if linktotal == 0 else linktotal)
                    out[i].append((str(linktotal).rjust(linksum_width)))
            out.append(["SUMMARY".ljust(link_width)])

            for coltotal in self.sum(axis=1, data=data):
                coltotal = (zero if coltotal == 0 else coltotal)
                out[-1].append((str(coltotal).rjust(column_width // nofdirs)))
            out[-1].append(str(total).rjust(linksum_width))

        return "\n".join(" ".join(lst) for lst in out)

    def tocsv(self, filepath, header=True, depth=5, data=None):
        """Exports self._data to CSV file in Excel dialect.

        Args:
            filepath (str): destination file name
            depth (int, optional): indicating how deep into the key
                to look into when grouping the links
            header (bool, optional): to write out column names
            data (dict, optional): self._data like OrderedDict

        Raises:
            ValueError: if depth is not a number from 1 to 5
        """
        if depth not in (1, 2, 3, 4, 5):
            raise ValueError(self.DEPTH_ERR)

        if data is None:
            data = self.groupby(depth=depth)

        if not data:
            return

        if sys.version_info.major == 3:
            kwarg = {"mode": "w", "newline": ""}
        else:
            kwarg = {"mode": "wb"}
        with open(filepath, **kwarg) as csvfile:
            writer = csv.writer(csvfile, dialect="excel")
            msgdirs = self.msgdirs(data)
            if header:
                dirmap = {self.dirOut: "OUT",
                          self.dirIn: "IN"}
                alink = next(iter(data.keys()))
                linksize = len(self._joinlink(alink, sep=" ").split())
                cols = ["server_ip", "client_ip", "proto",
                        "server_port", "client_port"][:linksize]
                row = self._joinlink(cols, sep=" ").split()
                for msgtype in self.msgtypes(data):
                    for msgdir in msgdirs:
                        row.append(" ".join((msgtype, dirmap.get(msgdir, ""))))
                writer.writerow(row)

            for link, cols in self.tocolumns(data).items():
                writer.writerow(self._joinlink(link, sep=" ").split() + cols)

    def dump(self, filepath):
        """Saves the instance to disk using the pickle library.

        Args:
            filepath (str): destination file including path
        """
        with open(filepath, "wb") as outfile:
            pickle.dump(self, outfile)

    def load(self, filepath):
        """Loads a saved instance from a pickle file.

        Args:
            filepath (str): source file including path

        Returns:
            SIPCounter: a SIPCounter object
        """
        with open(filepath, "rb") as infile:
            obj = pickle.load(infile)
        return obj

    def __contains__(self, thing):
        """Magic method to implement membership check ('in' operator).

        Note:
            Calling self.msgtypes() many in a loop is best to be
            avoided but saving the return value of this method
            to a local variable and use that in the loop.

        Args:
            thing (str, int): IP address or port or SIP message type

        Returns:
            bool: indicating if elem is in self._data
        """
        if isinstance(thing, int) or "." in thing:
            return any((thing in link) for link in self._data)
        if thing in ("TLS", "TCP", "UDP", self.local_name, self.remote_name):
            return True
        return thing in self.msgtypes()

    def __add__(self, other):
        """Magic method to implement addition of two SIPCounters together.

        Args:
            other (SIPCounter): the other SIPCounter object
        """
        if type(self) != type(other):
            raise TypeError(self.TYPEMISMADD_ERR)
        if not set(self.msgdirs()) & set(other.msgdirs()):
            raise TypeError(self.TYPEMISMDIR_ERR)

        dup = deepcopy(self._data)
        self.update(other.data)
        new = deepcopy(self._data)
        self._data = dup
        return SIPCounter(
            sip_filter=self.sip_filter,
            host_filter=self.host_filter,
            known_servers=self.known_servers,
            known_ports=self.known_ports,
            name=self.name,
            data=new
        )

    def __sub__(self, other):
        """Magic method to implement subtraction of a SIPCounter from another.

        Args:
            other (SIPCounter): the other SIPCounter object
        """
        if type(self) != type(other):
            raise TypeError(self.TYPEMISMSUB_ERR)
        if not set(self.msgdirs()) & set(other.msgdirs()):
            raise TypeError(self.TYPEMISMDIR_ERR)

        dup = deepcopy(self._data)
        self.subtract(other.data)
        new = deepcopy(self._data)
        self._data = dup
        return SIPCounter(
            sip_filter=self.sip_filter,
            host_filter=self.host_filter,
            known_servers=self.known_servers,
            known_ports=self.known_ports,
            name=self.name,
            data=new,
        )

    def __iadd__(self, other):
        """Magic method to implement in-place addition of a SIPCounter.
        to self.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            SIPCounter: the addition of self and other SIPCounter
        """
        if type(self) != type(other):
            raise TypeError(self.TYPEMISMADD_ERR)
        if not set(self.msgdirs()) & set(other.msgdirs()):
            raise TypeError(self.TYPEMISMDIR_ERR)

        self.update(other.data)
        return self

    def __isub__(self, other):
        """Magic method to implement in-place subtraction of a SIPCounter.
        from self.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            SIPCounter: the subtraction of other SIPCounter from self
        """
        if type(self) != type(other):
            raise TypeError(self.TYPEMISMSUB_ERR)
        if not set(self.msgdirs()) & set(other.msgdirs()):
            raise TypeError(self.TYPEMISMDIR_ERR)

        self.subtract(other.data)
        return self

    def __lt__(self, other):
        """Magic method to implement < operator to compare two SIPCounters.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            bool: if self.total is less than other.total
        """
        return self.total < other.total

    def __gt__(self, other):
        """Magic method to implement > operator to compare two SIPCounters.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            bool: if self.total is greater than other.total
        """
        return self.total > other.total

    def __ge__(self, other):
        """Magic method to implement >= operator to compare two SIPCounters.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            bool: if self.total is greater or equal than other.total
        """
        return self.total >= other.total

    def __le__(self, other):
        """Magic method to implement <= operator to compare two SIPCounters.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            bool: if self.total is less or equal than other.total
        """
        return self.total <= other.total

    def __eq__(self, other):
        """Magic method to implement == operator to compare two SIPCounters.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            bool: if self.total is equal to other.total
        """
        return self.total == other.total

    def __ne__(self, other):
        """Magic method to implement != operator to compare two SIPCounters.

        Args:
            other (SIPCounter): the other SIPCounter object

        Returns:
            bool: if self.total is not equal to other.total
        """
        return self.total != other.total

    def __repr__(self):
        """Magic method to return the representation of self.

        Returns:
            str: string representation of self
        """
        r = (
            'name="%s"',
            "sip_filter=%s",
            "host_filter=%s",
            "host_exclude=%s",
            "known_servers=%s",
            "known_ports=%s",
            "greedy=%s",
            "data=%s",
        )
        r = ", ".join(r) % (
            self.name,
            self.sip_filter,
            self.host_filter,
            self.host_exclude,
            self.known_servers,
            self.known_ports,
            self.greedy,
            self._data,
        )
        return "SIPCounter(%s)" % r

    def __str__(self):
        return "<%s instance at %s>" % (self.__class__.__name__, id(self))


if __name__ == "__main__":
    # sample output
    data1 = OrderedDict([
        (('local', 'remote', 'TCP', ''),
            {'<>': Counter({'INVITE': 110, '200': 1061, '503': 4})}),
        (('local', 'remote', 'TLS', ''),
            {'<>': Counter({'INVITE': 10, '200': 9, '603': 1})})])
    data2 = OrderedDict([
        (('192.168.100.100', '192.168.100.101', 'TCP', 5060, 61011),
            {'->': Counter({'INVITE': 100}),
             '<-': Counter({'200': 97, '503': 3})}),
        (('192.168.100.100', '192.168.100.101', 'TCP', 5060, 41774),
            {'<-': Counter({'INVITE': 10}),
             '->': Counter({'200': 9, '503': 1})}),
        (('192.168.100.100', '192.168.100.1', 'TLS', 5060, 44564),
            {'<-': Counter({'INVITE': 10}),
             '->': Counter({'200': 9, '603': 1})})])
    c1 = SIPCounter(data=data1, name="SIPCounter example simple")
    c2 = SIPCounter(data=data2, name="SIPCounter example full")
    print()
    print(c1.tostring(link_margin=16, zeros=False))
    print()
    print(c2.tostring(title="2020-08-09 23:58:00"))

