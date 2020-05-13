"""SIPCounter: counts SIP messages."""

import re
from collections import defaultdict, Counter, OrderedDict
from copy import deepcopy
from itertools import chain
from operator import itemgetter

__version__ = "0.0.1"


class SIPCounter(object):
    """Implements a simple, stateless SIP message counter with optional
    direction, IP address, protocol and port tracking. When provided with
    the IP address/protocol/port in addition to the mandatory SIP message
    body as strings it counts the SIP requests and responses for each
    communication link. A link thus is comprised of the SIP UA server and
    client IP addresses, the ports and the transport protocol type (TLS,
    TCP, UDP) which can also be inferred from the SIP message body if
    not supplied.
    """

    ORDER = {
        "INVITE": 0,
        "ReINVITE": 1,
        "BYE": 2,
        "CANCEL": 3,
        "UPDATE": 4,
        "NOTIFY": 5,
        "SUBSCRIBE": 6,
        "PUBLISH": 7,
        "ACK": 8,
        "PRACK": 9,
        "REFER": 10,
        "OPTIONS": 11,
        "INFO": 12,
        "REGISTER": 13,
        "MESSAGE": 14,
        "PING": 15,
        "UNKNOWN": 16,
    }

    def __init__(self, **kwargs):
        """Initializes with the following possible keyword arguments:

        sip_filter: a collection of SIP message types, out of which is
                    compiled a regex object to match only the request
                    and response types provided in this collection. If
                    not provided a default ".*" pattern is used which
                    will match all requests and responses.

                    For example to count only INVITE and ReINVITE
                    messages and any error responses for these requests
                    one should pass the following tuple, list or set:

                    sip_filter=set(["INVITE", "ReINVITE", "4", "5", "6"])

                    It is also possible to be more specific. For example:

                    sip_filter=set(["INVITE", "ReINVITE", "408", "503"])

        host_filter: a collection of host IP addresses, if the source or
                    destination IP address is supplied the SIP message will
                    only be counted if either the origin (srcip) or the
                    recipient (dstip) of the message is in this collection.

                    For example:

                    host_filter=set(["1.1.1.1", "2.2.2.2", "3.3.3.3"])

        known_servers: a collection of host IP addesses known to be SIP
                    servers, proxies or other SIP UA which the user would
                    like to consider as "servers". The internal logic of
                    this class tries to guess the server (or Local) and
                    client (or Remote) side automatically based on the
                    received message direction (msgdir if provided) or
                    port number (srcport, dstport if provided). If this
                    logic fails to determine correctly the role of the
                    communicating parties then the data may end up being
                    counted under a new link as opposed to an already
                    existing link or a link (dictionary key) will be
                    created with order swopped.
                    This argument serves as a helper and takes precedence
                    over any other supplied information used to guess
                    the role of the hosts.

                    For example:

                    known_servers=set(["1.1.1.2", "1.1.1.1"])

        known_ports: a collection of port numbers known to be used by
                    SIP servers, proxies, or entites the user would like
                    to consider as servers. This is yet another helper
                    set to assist in the determination of roles. This may
                    only be required if the SIP service is not running on
                    the well-known SIP ports which are 5060 or 5061.

                    For example:

                    known_ports=set(["5070", "5080"])

        data:       In rare situations there may be a need to initialize
                    an instance with some prepopulated counts prior to
                    incrementing the counters through the "update" or
                    "add" methods. This argument has to have the same
                    format as the internal self._data storeage.

                    For example:

                    {(
                        "<server ip>",    # tuple of strings as key
                        "<client ip>",
                        "<protocol>",
                        "<service port>",
                        "<client port>"
                     ):
                        {"msgdir1" : Counter(
                                                {
                                                  "<sip message type1>" : int,
                                                  "<sip message type2>" : int,
                                                }
                                            )
                        },
                        {"msgdir2" : Counter(
                                                {
                                                   "<sip message type1>" : int,
                                                   "<sip message type2>" : int,
                                                }
                                            )
                        },
                    }

                    For example to initialize an instance with some data:

                    data={("1.1.1.1", "2.2.2.2", "tcp", "5060", "34556"):
                    {"<-": Counter({"INVITE": 1, "ReINVITE": 1}),
                     "->": Counter({"200": 1, "100": 1})}}

        name:       the name of the class instance, for example it can
                    store the name of the host where the SIP messages
                    are captured.

        :param      sip_filter: (collection) SIP message capture filter
                    host_filter: (collection) SIP host capture filter
                    known_servers: (collection) known SIP servers/proxies
                    known_ports: (collection) known SIP services ports
                                 excluding 5060, 5061
                    data: (dict) to prepopulate self._data
                    name: (string) name of the instance
        """
        self.sip_filter = set(kwargs.get("sip_filter", [".*"]))
        self.host_filter = set(kwargs.get("host_filter", []))
        self.known_servers = set(kwargs.get("known_servers", []))
        self.known_ports = set(str(x) for x in kwargs.get("known_ports", []))
        self._data = kwargs.get("data", {})
        self.name = str(kwargs.get("name", ""))
        self.dirIn = "<-"
        self.dirOut = "->"
        self.dirBoth = "<>"
        self.local = "local"
        self.remote = "remote"
        self.known_ports = self.known_ports | set(["5060", "5061"])
        self.reSIPFilter = re.compile(r"(%s)" % "|".join(self.sip_filter))
        self.reReINVITE = re.compile(r"(To:|t:) .*(tag=)", re.MULTILINE)
        self.reCSeq = re.compile(r"CSeq: \d+ (\w+)", re.MULTILINE)
        self.reVia = re.compile(r"(Via:|v:) SIP/2.0/(.*) ", re.MULTILINE)

    @property
    def data(self):
        """Returns the internal self._data.
        :return: (dict)
        """
        return self._data

    @property
    def total(self):
        """Sums up all the Counter() objects found in self._data.
        :return: (int)
        """
        return sum(
            z for x in self._data.values() for y in x.values() for z in y.values()
        )

    def add(self, sipmsg, msgdir=None, *args):
        """Populate the Counters with a SIP message.
        :param sipmsg: (string) the SIP message body
        :param msgdir: (string) indicates the direction of the message
                        and consequently the order in which the hosts
                        (if provided) are placed in the self._data
                        dictionary as key. The direction can
                        be "IN" for incoming or else for outgoing.
        :param args:   (tuple of strings) contains the details of the
                        communicating parties in the order shown below:

                        (srcip, srcport, dstip, dstport, [proto])

                        the [proto]col is optional, if not provided it
                        will be extracted from the top Via header.

                        For example both are valid for args:

                        ("1.1.1.1", "5060", "2.2.2.2", "34556", "TCP")
                        ("1.1.1.1", "5060", "2.2.2.2", "34556")

                        In the example above since the srcport is a
                        well-known SIP service port and the other is not
                        and the known_servers keyword argument or the lack
                        of it also does not indicate neither IP address
                        to be a server, furthermore nor does the
                        known_ports keyword argument dictate otherwise
                        the SIP message will be counted towards the
                        following link in self._data with key:

                        ("1.1.1.1", "2.2.2.2", "tcp", "5060", "34556")

                        Any further messages between these two entities
                        using parameters listed in the tuple above will
                        be counted under the same key.
        :return: None
        """
        sipmsg = sipmsg.lstrip()
        if args:
            (srcip, srcport, dstip, dstport), proto = args[0:4], args[4:]
            if self.host_filter and (
                srcip not in self.host_filter and dstip not in self.host_filter
            ):
                return
        if sipmsg.startswith("SIP"):
            msgtype = sipmsg.split(" ", 2)[1]
        else:
            msgtype = sipmsg.split(" ", 1)[0]
            if msgtype == "INVITE" and self.reReINVITE.search(sipmsg):
                msgtype = "ReINVITE"
        m = self.reCSeq.search(sipmsg)
        if m:
            method = m.group(1)
        elif msgtype[0].isdigit():
            method = "UNKNOWN"
        else:
            method = msgtype

        # Determining direction
        if msgdir is not None:
            if msgdir.upper() == "IN":
                msgdir = self.dirIn
            else:
                msgdir = self.dirOut
        elif args:
            if self.known_servers:
                if srcip in self.known_servers:
                    msgdir = self.dirOut
                elif dstip in self.known_servers:
                    msgdir = self.dirIn
            elif self.known_ports:
                if str(dstport) in self.known_ports:
                    msgdir = self.dirIn
                elif str(srcport) in self.known_ports:
                    msgdir = self.dirOut
            else:
                if int(srcport) > int(dstport):
                    msgdir = self.dirIn
                elif int(srcport) < int(dstport):
                    msgdir = self.dirOut
                elif srcip > dstip:
                    msgdir = self.dirIn
                else:
                    msgdir = self.dirOut
        else:
            msgdir = self.dirBoth

        # Determining server/client side
        if args:
            if msgdir == self.dirIn:
                link = [dstip, srcip]
            else:
                link = [srcip, dstip]

            # Determining server/client ports
            if str(srcport) in self.known_ports:
                service_port = srcport
                client_port = dstport
            elif str(dstport) in self.known_ports:
                service_port = dstport
                client_port = srcport
            elif int(srcport) > int(dstport):
                service_port = dstport
                client_port = srcport
            else:
                service_port = srcport
                client_port = dstport
        else:
            link = [self.local, self.remote]
            service_port, client_port = "", ""

        # Determining protocol
        if args and proto:
            proto = proto[0]
        else:
            m = self.reVia.search(sipmsg)
            if m:
                proto = m.group(2)
            else:
                proto = "UDP"
        link.extend([proto.upper(), str(service_port), str(client_port)])
        if self.reSIPFilter.match(method) and self.reSIPFilter.match(msgtype):
            (
                self._data.setdefault(tuple(link), {})
                .setdefault(msgdir, Counter())
                .update([msgtype])
            )

    def update(self, iterable):
        """Updates the internal Counters directly . It is unlikely to be used
        often directly bypassing the logic of 'add' method.
        :param iterable: (dict) of the same type as the self._data
                         it's primary purpose is to allow access to the
                         internal collections.Counters in order to update
                         their values directly post initialization.

                         For example:

                         {("1.1.1.1", "2.2.2.2", "tcp", "5060", "34556"):
                         {"<-": Counter({"UPDATE": 1, "ReINVITE": 1}),
                         "->": Counter({"200": 1, "100": 1})}}

        :return: None
        """
        if isinstance(iterable, dict):
            for k, v in iterable.items():
                for k2, v2 in v.items():
                    (self._data.setdefault(k, {})
                         .setdefault(k2, Counter())
                         .update(v2))

    def subtract(self, iterable, compact=True):
        """Subtract the iteable from the self._data store.

        :param iterable: (dict) of the same type as the self._data,
                         it's primary purpose is the same as that of
                         the update method but instead of addition it
                         subtracts the Counter values provided in the
                         iterable argument frpm the internal self._data.
                         The provided values will only be removed if
                         self._data contains the SIP message type for
                         the same link and same direction found in
                         the provided iterable.
        :param compact: (bool) if a link with all zero or less than zero
                        values is to be removed from self._data
        :return: None
        """
        if isinstance(iterable, dict):
            for k, v in iterable.items():
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
        """Clears the self._data dictionary. This can be used when for
        example a new sampling period begins and the counting needs
        to start from zero.
        :return: None
        """
        self._data.clear()

    def compact(self):
        """Removes links and message types with Counter values 0 or less
        for all message types.
        """
        data = {}
        for k, v in self._data.items():
            for k2, v2 in v.items():
                for k3, v3 in v2.items():
                    if v3 > 0:
                        (
                            data.setdefault(k, {})
                            .setdefault(k2, Counter())
                            .update({k3: v3})
                        )
        self._data = data

    def items(self):
        """Returns the key,value pairs of the self._data dictionary.
        :return: (iterator)
        """
        return self._data.items()

    def keys(self):
        """Returns the keys (aka links) of the self._data dictionary.
        :return: (iterator)
        """
        return self._data.keys()

    def links(self):
        """The same as self.keys() above.
        :return: (iterator)
        """
        return self.keys()

    def values(self):
        """Returns the values of the self._data dictionary.
        :return: (iterator)
        """
        return self._data.values()

    def groupby(self, depth=4):
        """This method has two purposes. One is to group together the
        links by the depth the caller looks into the self._data keys.
        The other is to order the grouped elements. Let's assume there
        are five separate links in the self._data as follows:

        {("1.1.1.1", "2.2.2.2", "tcp", "5060", "33332"):  {"<-": Counter({"INVITE": 1})},
         ("1.1.1.1", "2.2.2.2", "tcp", "5060", "33333"):  {"<-": Counter({"INVITE": 1})},
         ("1.1.1.1", "3.3.3.3", "tcp", "5060", "33334"):  {"<-": Counter({"INVITE": 1})},
         ("1.1.1.1", "2.2.2.2", "tcp", "5062", "33335"):  {"<-": Counter({"INVITE": 1})},
         ("1.1.1.1", "2.2.2.2", "tls", "5061", "33336"):  {"<-": Counter({"INVITE": 1})}}

        Calling groupby(depth=5) would only sort and return an
        OrderedDict placing the Counters between "1.1.1.1" and "2.2.2.2"
        first before that of "1.1.1.1" and "3.3.3.3".

        Calling groupby(depth=4), default, would not only sort the links
        but also merge the Counters of "1.1.1.1" and "2.2.2.2" over
        "tcp", port "5060" ignoring the client side ports. It returns:

        OrderedDict([.....
        ("1.1.1.1", "2.2.2.2", "tcp", "5060"):  {"<-": Counter({"INVITE": 2})},
        ("1.1.1.1", "2.2.2.2", "tcp", "5062"):  {"<-": Counter({"INVITE": 1})},
        ("1.1.1.1", "2.2.2.2", "tls", "5061"):  {"<-": Counter({"INVITE": 1})},
        ("1.1.1.1", "3.3.3.3", "tcp", "5060"):  {"<-": Counter({"INVITE": 1})},
        ...])

        Calling groupby(depth=3) would order and merge the Counters of
        "1.1.1.1" and "2.2.2.2" over "tcp" regardless of the server
        or client side ports used.

        OrderedDict([.....
        ("1.1.1.1", "2.2.2.2", "tcp"), {"<-": Counter({"INVITE": 3})}),
        ("1.1.1.1", "2.2.2.2", "tls"), {"<-": Counter({"INVITE": 1})}),
        ("1.1.1.1", "3.3.3.3", "tcp"), {"<-": Counter({"INVITE": 1})}),
        ...])

        Calling groupby(depth=2) would merge even further the Counters
        in addition to sorting them, ignoring the protocol as well.

        OrderedDict([.....
        ("1.1.1.1", "2.2.2.2"), {"<-": Counter({"INVITE": 4})}),
        ("1.1.1.1", "3.3.3.3"), {"<-": Counter({"INVITE": 1})}),
        ...])

        And so on.

        :param depth: (int) indicating how deep into the key, which is
                      a tuple of potentially five strings elements,
                      the method should look into when grouping the
                      Counters.
        :return: (OrderedDict) grouped and ordered by server/client IP
                 and protocol.
        """
        depth = max(min(5, int(depth)), 0)

        if depth == 5:
            g = self._data
        else:
            g = {}
            for link in self.keys():
                if set(link[0:depth]).issubset(link):
                    for k in self._data[link]:
                        (
                            g.setdefault(link[0:depth], {})
                            .setdefault(k, Counter())
                            .update(self._data[link][k])
                        )
        l = sorted(g.keys(), key=(depth and itemgetter(*range(0, depth))
                                        or None))
        return OrderedDict((k, g[k]) for k in l)

    def most_common(self, n=None, depth=4):
        """Returns an OrderedDict of the 'n' busiest links in descending
        order. Optionally it groups (merges) links depending on how
        many elements of the key is to be considered significant.
        :param n: (int) how many of the busiest links to return
        :param depth: (int) indicating how deep into the key the method
                      should look into when grouping the links.
        :return: (OrderedDict) grouped and ordered by server/client IP
                 and protocol.
        """
        g = self.groupby(depth=depth)
        d = defaultdict(int)

        for k, v in g.items():
            for counter in v.values():
                d[k] += sum(counter.values())

        most = sorted(d, key=d.get, reverse=True)
        if n is not None:
            most = most[0:n]
        return OrderedDict([(x, g[x]) for x in most])

    def summary(self, data=None, title="SUMMARY"):
        """Returns a dictionary with the summary of all Counters for
        each SIP message type in self._data or on the optional
        self._data like "data" dictionary.
        :param data: (dict) optional self._data like dictionary
        :param title: (string) optional key name of the dictionary
        :return: (dict) with the summary of all Counters.
        """
        if data is None:
            data = self._data
        # d = OrderedDict({(title,) : {}})
        d = {(title,): {}}

        for v in data.values():
            for direction, counter in v.items():
                d[(title,)].setdefault(direction, Counter()).update(counter)
        return d

    def elements(self, data=None):
        """Returns a list of SIP message types found in self._data or
        in the optionally provided self._data like "data" dictionary.
        :param data: (dict) optional self._data like dictionary
        :return: (list) list of strings of all the SIP message types
        """
        if data is None:
            data = self._data

        s = set(x for s in data.values() for y in s.values() for x in y)
        requests = sorted(
            (x for x in s if not x.isdigit()),
            key=lambda x: self.ORDER.get(x, len(self.ORDER)),
        )
        responses = sorted((x for x in s if x.isdigit()))
        return requests + responses

    def pprint(self, depth=4, title="", header=True, links=True, summary=True,
               data=None):
        """
        A convenience method to provide a basic easy to read output of
        the self._data dictionary.
        :param depth: (int) indicating how deep into the key, the method
                      should look into when grouping the links.
        :param title: (string) optional information to print inline
                      with top line, for example a timestamp
        :param header: (bool) if the header is to be printed
        :param links: (bool) if the individual links are to be printed
        :param summary: (bool) if summary line is to be printed
        :param data: (dict) optional self._data like dictionary to pprint

                     For example to pprint the busiest 5 links:

                     print(sipcounter.pprint(data=sipcounter.most_common(n=5)))

        :return: (string) a formated representation of self._data
        """
        output = []
        if data is None:
            data = self.groupby(depth=depth)
        if not data:
            return ""
        elif summary:
            s = self.summary(data=data)
            sl = len("".join(list(s.keys())[0]))
        else:
            s = self.most_common(depth=depth)
            sl = 0
        if any(x for v in data.values() for x in v.keys() if x == self.dirBoth):
            directions = 1
        else:
            directions = 2
        m = s[list(s.keys())[0]]
        elements = self.elements(data=data)
        cl = max(len(str(x)) for v in m.values() for x in v.values())
        ml = max(len(x) for x in elements)
        ll = max((len("".join(x)) for x in data.keys())) + int(depth)
        column_width = int(round(max(ml, cl * directions) / 2) * 2) + 1
        link_width = max(ll, len(self.name), sl, len(title)) + 1
        if header:
            output.append("")
            columns = " ".join(x.center(column_width) for x in elements)
            output.append(title.ljust(link_width) + columns)
            if directions > 1:
                output.append(
                    "".join(
                        (
                            self.name.ljust(link_width),
                            len(elements)
                            * (
                                " ".join(
                                    (
                                        self.dirOut.rjust(
                                            column_width // directions, "-"
                                        ),
                                        self.dirIn.ljust(
                                            column_width // directions, "-"
                                        ),
                                    )
                                )
                                + " "
                            ),
                        )
                    )
                )
            else:
                output.append(
                    "".join(
                        (
                            self.name.ljust(link_width),
                            len(elements)
                            * ("".join(("-".center(column_width, "-"))) + " "),
                        )
                    )
                )
        l = []
        if links:
            l.append(data)
        if summary:
            l.append(s)
        for d in chain(l):
            for k in d.keys():
                c = []
                link = "-".join(
                    x
                    for x in (
                        "".join(k[0:1]),
                        "".join(k[2:3]),
                        "".join(k[3:4]),
                        "".join(k[4:5]),
                        "".join(k[1:2]),
                    )
                    if x
                )
                for elem in elements:
                    if directions > 1:
                        c.append(str(d[k].get(self.dirOut, {}).get(elem, 0)))
                        c.append(str(d[k].get(self.dirIn, {}).get(elem, 0)))
                    else:
                        c.append(str(d[k].get(self.dirBoth, {}).get(elem, 0)))
                output.append(
                    "".join(
                        (
                            link.ljust(link_width),
                            " ".join(x.rjust(column_width // directions) for x in c),
                        )
                    )
                )
        output.append("")
        return "\n".join(output)

    def __contains__(self, elem):
        """Magic method to implement membership check ('in' operator)
        :return: None"""
        elem = str(elem)
        if "." in elem or (elem.isdigit() and len(elem) > 3):
            return any(elem in x for x in self._data)
        return elem in self.elements()

    def __add__(self, other):
        """Magic method to add two SIPCounters together
        :return: None"""
        if type(self) != type(other):
            raise TypeError("can only add SIPCounter to a SIPCounter")
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
            data=new,
        )

    def __sub__(self, other):
        """Magic method to subtract a SiPCounter from another
        :return: None"""
        if type(self) != type(other):
            raise TypeError("can only subtract SIPCounter from a SIPCounter")
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
        """Magic method to add a SIPCounter to self._data inplace
        :return: None"""
        if type(self) != type(other):
            raise TypeError("can only add SIPCounter to a SIPCounter")
        self.update(other.data)
        return self

    def __isub__(self, other):
        """Magic method to subtract a SIPCounter from self._data inplace
        :return: None"""
        if type(self) != type(other):
            raise TypeError("can only subtract SIPCounter from a SIPCounter")
        self.subtract(other.data)
        return self

    def __lt__(self, other):
        """Magic method to implement < operator to compare two SIPCounters
        :return: None"""
        return self.total < other.total

    def __gt__(self, other):
        """Magic method to implement > operator to compare two SIPCounters
        :return: None"""
        return self.total > other.total

    def __ge__(self, other):
        """Magic method to implement >= operator to compare two SIPCounters
        :return: None"""
        return self.total >= other.total

    def __le__(self, other):
        """Magic method to implement <= operator to compare two SIPCounters
        :return: None"""
        return self.total <= other.total

    def __eq__(self, other):
        """Magic method to implement == operator to compare two SIPCounters
        :return: None"""
        return self.total == other.total

    def __ne__(self, other):
        """Magic method to implement != operator to compare two SIPCounters
        :return: None"""
        return self.total != other.total

    def __repr__(self):
        r = (
            'name="%s"',
            "sip_filter=%s",
            "host_filter=%s",
            "known_servers=%s",
            "known_ports=%s",
            "data=%s",
        )
        r = ", ".join(r) % (
            self.name,
            self.sip_filter,
            self.host_filter,
            self.known_servers,
            self.known_ports,
            self._data,
        )
        return "SIPCounter(%s)" % r

    def __str__(self):
        return "<%s instance at %s>" % (self.__class__.__name__, id(self))
