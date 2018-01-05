from collections import defaultdict, Counter, OrderedDict
from copy import deepcopy
from itertools import chain
from operator import itemgetter
import re

class SIPCounter(object):
    """
    This class provides a SIP Counter. It can be used to track the number of
    SIP requests and corresponding responses. It is not meant to be a stateful
    call status tracking tool. It merely counts the messages sent/received.
    It's primary use would be to monitor links for certain type of events, for
    example an occurrences of certain SIP errors or provides basic statistics.
    For instance using the convenience pprint method you can visualize the type
    and number of SIP messages you are interested in.

        IPCounter               INVITE    NOTIFY    REFER    REGISTER    100       200       202
                              ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- ---> <---
    1.1.1.1-TCP-5060-2.2.2.2     0    0    0    0    0    0  641    0    0  795    0    0    0    0
    1.1.1.1-TCP-5062-2.2.2.2   934    0    0    0    0    0    0    0    0    0    0  670    0    0
    1.1.1.1-TLS-5061-2.2.2.2   838    0    0    0    0    0  132    0    0  582    0   11    0    0
    1.1.1.1-TCP-5060-3.3.3.3     0    0    0    0    0  122    0    0    0    0    0    0  378    0
    1.1.1.1-UDP-5060-3.3.3.3     0    0    0  415    0    0    0    0    0    0  799    0    0    0
    SUMMARY                   1772    0    0  415    0  122  773    0    0 1377  799  681  378    0

    """
    SORT_ORDER = {
        'INVITE': 0,
        'ReINVITE': 1,
        'BYE': 2,
        'CANCEL': 3,
        'UPDATE': 4,
        'NOTIFY': 5,
        'SUBSCRIBE': 6,
        'PUBLISH': 7,
        'ACK': 8,
        'PRACK': 9,
        'REFER': 10,
        'OPTIONS': 11,
        'INFO': 12,
        'PING': 13,
        'REGISTER': 14,
        'MESSAGE': 15,
        'UNKNOWN': 16,
    }
    def __init__(self, **kwargs):
        """
        Initializes a SIPCounter instance with optional keyword arguments.

        sip_filter: serves as a SIP message capture filter, out of which is
                    built a regex object which is used to match certain or all
                    request methods and corresponding responses.
                    If not provided the default '.*' is used which will match
                    all requests and responses.
                    For example to count only INVITE and ReINVITE messages
                    and any error response of these requests one should pass
                    a set as follows:

                    sip_filter=set(['INVITE', 'ReINVITE', '4', '5', '6'])

                    It is also possible to define more specifically the error,
                    for example:

                    sip_filter=set(['INVITE', 'ReINVITE', '408, '487', '5', '6'])

        host_filter: serves as a host capture filter, if the source and/or
                    destination IP address of the SIP message is provided it
                    will be counted only of either the origin (srcip) ir the
                    recipient (dstip) of the SIP message is in this set.
                    For example to pass this argument:

                    host_filter=set(['1.1.1.1', '2.2.2.2', '3.3.3.3'])

        known_servers: this serves as a helper to the logic which determines
                    which of the two communicating parties may be the SIP
                    Server/Proxy and the Client. If the internal logic fails
                    to determine correctly the role of the communicating
                    parties then the link summary may end up showing the
                    parties in the wrong order and/or with wrong services port.
                    If so it could help to specify the IP addresses of the
                    SIP application servers/proxies/session border controllers.
                    For example:

                    known_servers=set(['1.1.1.2', '1.1.1.1'])


        known_ports: this is yet another helper to the logic which determines
                    which of the two communicating parties may be the SIP
                    Server/Proxy and the Client. If not well-known SIP
                    ports are used (other than '5060' and '5061') then it
                    may be a good idea to pass those none default ports
                    in this argument so that the report will come out nicely.
                    For example if the SIP service is running on port
                    5070 and 5080 use strings instead of integers:

                    known_ports=set(['5070', '5080'])

        data:       In rare situations there may be a need to initialize this
                    object with some data prior to adding the first SIP
                    message to the internal 'self._data' using the 'add'
                    or 'update' methods. The internal SIP data store of this
                    class instance is as follows:

                    {('server ip', 'client ip', 'protocol', 'service port', 'client port') :
                      {'msgdir' : collections.Counter()}, ....}

                    For example to initialize an instance with some data:

                    data={('1.1.1.1', '2.2.2.2', 'tcp', '5060', '34556'):
                    {'<-': Counter({'INVITE': 1}), '->': Counter({'200': 1})}}

        name:       this is used for housekeeping purposes, for example it can
                    store the name of the system where these messages are
                    captured or the date/timestamp since it is collecting data.


        :param kwargs: sip_filter (set): SIP message capture filter
                       host_filter (set): SIP host capture filter
                       known_servers (set): known SIP servers/proxies
                       known_ports (set): known SIP services ports in addition
                                          to the well-known port 5060 and 5061
                       data (dict): internal data storage of counters
                       name (string): name of this instance
        """
        self.sip_filter = kwargs.get('sip_filter', set(['.*']))
        self.host_filter = kwargs.get('host_filter', set())
        self.known_servers = kwargs.get('known_servers', set())
        self.known_ports = kwargs.get('known_ports', set()).union(set(['5060',
                                                                       '5061']))
        self.reSIPFilter = re.compile(r'(%s)' % '|'.join(self.sip_filter))
        self._data = kwargs.get('data', {})
        self.name = kwargs.get('name', '')
        self.dirIn = '<-'
        self.dirOut = '->'
        self.dirBoth = '<>'
        self.reReINVITE = re.compile(r'(To:|t:) .*(tag=)', re.MULTILINE)
        self.reCSeq = re.compile(r'(CSeq: .*)', re.MULTILINE)
        self.reVia = re.compile(r'(Via:|v:) .*', re.MULTILINE)

    @property
    def data(self):
        return self._data

    @property
    def total(self):
        return sum(z for x in self._data.values()
                     for y in x.values()
                     for z in y.values())

    def add(self, sipmsg, msgdir=None, *args):
        """
        :param sipmsg: (string): SIP message as a string
        :param msgdir: (string of 'IN' or 'OUT'): determines the direction of
                        the message and the order in which the communicating
                        parties are placed into the internal dictionary as key,
                        first is the Server/Proxy followed by the Client.
        :param args: (tuple of strings): this tuple contains in the order
                      depicted below the details of the communicating parties
                      (aka link):

                      (srcip, srcport, dstip, dstport, [proto])

                      the proto is optional, if not provided it will be
                      extracted from the top Via header.

                      For exaple both are valid for args:

                      ('1.1.1.1', '5060', '2.2.2.2', '34556', 'TCP')
                      ('1.1.1.1', '5060', '2.2.2.2', '34556')

                      Since the srcport is a well-known SIP service port
                      and the other is not then by default the message above
                      will be places into the internal dictionary - as a key -
                      as follows:

                      ('1.1.1.1', '2.2.2.2', 'tcp', '5060', '34556')

                      Any further messages between these two entities using TCP
                      and service port 5060 and client port 34556 will be
                      counted under this key.
        :return: None
        """
        if args:
            (srcip, srcport, dstip, dstport), proto = args[0:4], args[4:]
            if self.host_filter and (srcip not in self.host_filter and
                                     dstip not in self.host_filter):
                return

        if sipmsg.startswith('SIP'):
            msgtype = sipmsg.split(' ', 2)[1]
        else:
            msgtype = sipmsg.split(' ', 1)[0]
            if msgtype == 'INVITE' and self.reReINVITE.search(sipmsg):
                msgtype = 'ReINVITE'
            m = self.reCSeq.search(sipmsg)
            if m:
                method = m.group().split()[2]
            elif msgtype[0].isdigit():
                method = 'UNKNOWN'
            else:
                method = msgtype
        # Determining direction
        if msgdir is not None:
            if msgdir.upper() == 'IN':
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
                if dstport in self.known_ports:
                    msgdir = self.dirIn
                elif srcport in self.known_ports:
                    msgdir = self.dirOut
            else:
                if srcport > dstport:
                    msgdir = self.dirIn
                elif srcport < dstport:
                    msgdir = self.dirOut
                elif srcip > dstip:
                    msgdir = self.dirIn
                else:
                    msgdir = self.dirOut
        else:
            msgdir = self.dirBoth
        if args:    
            # Determining server/client side
            if msgdir == self.dirIn:
                link = [dstip, srcip]
            else:
                link = [srcip, dstip]
            # Determining server/client ports
            if srcport in self.known_ports:
                service_port = srcport
                client_port = dstport
            elif dstport in self.known_ports:
                service_port = dstport
                client_port = srcport
            elif int(srcport) > int(dstport):
                service_port = dstport
                client_port = srcport
            else:
                service_port = srcport
                client_port = dstport
            # Determining protocol
            if proto:
                proto = proto[0]
            else:
                m = self.reVia.search(sipmsg)
                if m:
                    proto = m.group()[13:16]
                else:
                    proto = 'udp'
            link.extend([proto.lower(), service_port, client_port])
        else:
            link = ['', '', '', '', '']
        if self.reSIPFilter.match(method) and self.reSIPFilter.match(msgtype):
            self._data.setdefault(tuple(link), {}
                     ).setdefault(msgdir, Counter()
                     ).update([msgtype])

    def update(self, iterable, subtract=False):
        """
        This method serves to modify the internal Counters directly.
        Many other methods use this internally. It is very unlikely
        to be used often directly by the consumer of this Class.
        :param iterable: (dict): of the same type as the internal self._data
                         it is primary purpose is to allow access to the
                         internal collections.Counters in order to update
                         their values. It is very unlikely to be used often
                         directly.

                         For example:

                         {('1.1.1.1', '2.2.2.2', 'tcp', '5060', '34556'):
                         {'<-': Counter({'UPDATE': 1, 'ReINVITE': 1}),
                         '->': Counter({'200': 1, '100': 1})}}

        :param subtract: (bool): if the internal Counter is to be
                                 subtracted from and not added to.
        :return: None
        """
        if isinstance(iterable, dict):
            for k, v in iterable.iteritems():
                for k2, v2 in v.iteritems():
                    if not subtract:
                        self._data.setdefault(k, {}
                                 ).setdefault(k2, Counter()
                                 ).update(v2)
                    else:
                        self._data.setdefault(k, {}
                                 ).setdefault(k2, Counter()
                                 ).subtract(v2)

    def clear(self):
        """
        Clears the internal data store. This can be used when for example
        a new sampling period begins and everything needs to be cleared.
        :return: None
        """
        self._data.clear()

    def iteritems(self):
        """
        Returns the key,value pairs of the self._data storage.
        :return: (generator)
        """
        return self._data.iteritems()

    def iterkeys(self):
        """
        Returns the keys (aka links) of the self._data storage.
        :return: (generator)
        """
        return self._data.iterkeys()

    def keys(self):
        """
        Provides the list of internal storage keys (aka links) sorted
                 by Server/Proxy IP, then Client IP, then protocol,
                 followed by Server side port then Client side port
        :return: (list)
        """
        return sorted(self._data.iterkeys(), key=itemgetter(0, 1, 2, 3))

    def groupby(self, depth=4):
        """
        Has two purposes. One is to group (or add) together the Counters
        of links depending on how deep the caller would like to look into
        the self._data storage. The other is to order the grouped
        dictionary. For example there are five separate links in the
        self._data as follows:

        {('1.1.1.1', '2.2.2.2', 'tcp', '5060', '33332'):  {'<-': Counter({'UPDATE': 1})},
         ('1.1.1.1', '2.2.2.2', 'tcp', '5060', '33333'):  {'<-': Counter({'UPDATE': 1})},
         ('1.1.1.1', '3.3.3.3', 'tcp', '5060', '33334'):  {'<-': Counter({'UPDATE': 1})},
         ('1.1.1.1', '2.2.2.2', 'tcp', '5062', '33335'):  {'<-': Counter({'UPDATE': 1})},
         ('1.1.1.1', '2.2.2.2', 'tls', '5061', '33336'):  {'<-': Counter({'UPDATE': 1})}}

        Calling groupby(depth=5) would only return an OrderedDict placing the
        Counters between '1.1.1.1' and '2.2.2.2' first before that of '1.1.1.1'
        with '3.3.3.3'.
        Calling groupby(depth=4) would not only order the links but also merge
        the Counters of '1.1.1.1' and '2.2.2.2' over 'tcp', port '5060'
        regardless of the client side port used.

        OrderedDict([.....
        ('1.1.1.1', '2.2.2.2', 'tcp', '5060'):  {'<-': Counter({'UPDATE': 2})},
        ('1.1.1.1', '2.2.2.2', 'tcp', '5062'):  {'<-': Counter({'UPDATE': 1})},
        ('1.1.1.1', '2.2.2.2', 'tls', '5061'):  {'<-': Counter({'UPDATE': 1})},
        ('1.1.1.1', '3.3.3.3', 'tcp', '5060'):  {'<-': Counter({'UPDATE': 1})},
        ...])

        Calling groupby(depth=3) would order and merge the Counters of
        '1.1.1.1' and '2.2.2.2' over 'tcp' regardless of the server
        or client side port used.

        OrderedDict([.....
        ('1.1.1.1', '2.2.2.2', 'tcp'), {'<-': Counter({'UPDATE': 3})}),
        ('1.1.1.1', '2.2.2.2', 'tls'), {'<-': Counter({'UPDATE': 1})}),
        ('1.1.1.1', '3.3.3.3', 'tcp'), {'<-': Counter({'UPDATE': 1})}),
        ...])

        Calling groupby(depth=2) would merge even further the Counters in
        addition to ordering them:

        OrderedDict([.....
        ('1.1.1.1', '2.2.2.2'), {'<-': Counter({'UPDATE': 4})}),
        ('1.1.1.1', '3.3.3.3'), {'<-': Counter({'UPDATE': 1})}),
        ...])

        :param depth: (int): indicating how deep into the key, which is a
        tuple of potentially five strings, the method should look into when
        grouping the Counters together.
        :return: (OrderedDict): grouped and ordered by Server/Client/Protocol
        """
        depth = max(min(5, int(depth)), 0)
        if depth == 5:
            g = self._data
        else:
            g = {}
            for link in self.keys():
                if set(link[0:depth]).issubset(link):
                    for k in self._data[link]:
                        g.setdefault(link[0:depth], {}
                        ).setdefault(k, Counter()
                        ).update(self._data[link][k])
        l = sorted(g.iterkeys(), key=depth and itemgetter(*range(0, depth))
                                           or None)
        return OrderedDict((k, g[k]) for k in l)

    def most_common(self, n=None, depth=4):
        """
        Calculates the list of links with the highest total number of SIP
        messages exchanged in descending order. Returns an OrderedDict
        with the Counters of the n'th number of busiest links, optionally
        grouped (merged) as well.
        :param n: (int): how many of the most chatty links to return
        :param depth: (int): indicating how deep into the key, which is a
        tuple of potentially four strings, the method should look into when
        grouping the Counters together.
        :return: (OrderedDict): grouped and ordered by Server/Client/Protocol
        """
        g = self.groupby(depth=depth)
        d = defaultdict(int)
        for k,v in g.iteritems():
            for _, counter in v.iteritems():
                d[k] += sum(counter.values())
        most = sorted(d, key=d.get, reverse=True)
        if n is not None:
            most = most[0:n]
        return OrderedDict([(x, g[x]) for x in most])

    def summary(self, data=None, title='SUMMARY'):
        """
        Calculates and returns a dictionary with the summary of all
        the Counters either seen in the internal self._data store or in
        a similar data store provided in optional 'data' argument.
        :param data: (dict): optional self._data store like dictionary
        :param title: (string): optional name of the summary line
        :return: (dict): with the summary of all Counters
        """
        if data is None:
            data = self._data
        d = OrderedDict({(title,) : {}})
        for k,v in data.iteritems():
            for direction, counter in v.iteritems():
                d[(title,)].setdefault(direction, Counter()).update(counter)
        return d

    def elements(self, data=None):
        """
        Provides the list of SIP message types captured either in the internal
        self._data store or in the optionally provided dictionary.
        :param data: (dict): optional self._data store like dictionary
        :return: (list): list of strings of all the SIP message types
        """
        if data is None:
            data = self._data
        s = set(x for s in data.values() for y in s.values() for x in y)
        requests = sorted((x for x in s if not x.isdigit()),
                   key=lambda x: self.SORT_ORDER.get(x, len(self.SORT_ORDER)))
        responses = sorted((x for x in s if x.isdigit()))
        return requests + responses

    def pprint(self, links=True, summary=True, depth=4, header=True, data=None):
        """
        Convenience method to provide a basic readable output of the internal
        self._data store. The representation of the self._data is subjective,
        therefore it was not the primary objective of this Class is provide
        a full fledged pretty print method. Consumers are encouraged to write
        their own functions to present the content of the internal data
        store the way that best suits their needs.
        :param links: (bool): if the link lines are to be printed
        :param summary: (bool): if summary line is to be printed in the end
        :param depth: (int): indicating how deep into the key, which is a
        tuple of potentially four strings, the method should look into when
        grouping the Counters together.
        :param header: (bool): if the header is to be printed
        :param data: optional self._data store like dictionary, this may be
                     used more often. For example to pprint the busiest
                     5 links one can use this as follows:

                     print sipcounter.pprint(data=sipcounter.most_common(n=5))

        :return: (string): ready to be printed to the screen
        """
        output = []
        if data is None:
            data = self.groupby(depth=depth)
        if summary:
            s = self.summary(data=data)
            sl = len(''.join(next(s.iterkeys())))
        else:
            s = self.most_common(depth=depth)
            sl = 0
        if any(x for _,v in data.iteritems() 
                 for x in v.iterkeys() if x == self.dirBoth):
            directions = 1
        else:
            directions = 2
        m = s[next(s.iterkeys())]
        elements = self.elements(data=data)
        cl = max(len(str(x)) for v in m.values() for x in v.values())
        ml = max(len(x) for x in elements)
        ll = max((len(''.join(x)) for x in data.iterkeys())) + int(depth)
        column_width = int(round(max(ml, cl*directions)/2)*2) + 1
        link_width = max(ll, len(self.name), sl) + 1
        if header:
            output.append('')
            columns = ' '.join(x.center(column_width) for x in elements)
            output.append(self.name.ljust(link_width) + columns)
            if directions > 1:
                output.append(''.join((
                    ''.ljust(link_width),
                    len(elements) * (
                        ' '.join((
                        self.dirOut.rjust(column_width/directions, '-'),
                        self.dirIn.ljust(column_width/directions, '-')))
                        + ' ')
                            )))
            else:
                output.append(''.join((
                    ''.ljust(link_width),
                    len(elements) * (
                        ''.join(('-'.center(column_width, '-'))) + ' ')
                             )))
        l = []
        if links:
            l.append(data)
        if summary:
            l.append(s)
        for d in chain(l):
            for k,v in d.iteritems():
                c = []
                link = '-'.join(x for x in (
                                ''.join(k[0:1]),
                                ''.join(k[2:3]),
                                ''.join(k[3:4]),
                                ''.join(k[4:5]),
                                ''.join(k[1:2]),
                                ) if x)
                for elem in elements:
                    if directions > 1:
                        c.append(str(d[k].get(self.dirOut, {}).get(elem, 0)))
                        c.append(str(d[k].get(self.dirIn, {}).get(elem, 0)))
                    else:
                        c.append(str(d[k].get(self.dirBoth, {}).get(elem, 0)))
                output.append(
                    ''.join((
                        link.ljust(link_width),
                        ' '.join(x.rjust(column_width/directions) for x in c)
                            )))
        output.append('')
        return '\n'.join(output)

    def __contains__(self, elem):
        if '.' in elem:
            return any(elem in x for x in self._data)
        return elem in self.elements()

    def __add__(self, other):
        if type(self) != type(other):
            raise TypeError('can only add SIPCounter to another SIPCounter')
        sip_filter = self.sip_filter | other.sip_filter
        host_filter = self.host_filter | other.host_filter
        known_servers = self.known_servers | other.known_servers
        known_ports = self.known_ports | other.known_ports
        name = ' '.join((self.name, other.name))
        dup = deepcopy(self._data)
        self.update(other.data)
        new = deepcopy(self._data)
        self._data = dup
        return SIPCounter(sip_filte=sip_filter,
                          host_filter=host_filter,
                          known_servers=known_servers,
                          known_ports=known_ports,
                          name=name,
                          data=new)

    def __sub__(self, other):
        if type(self) != type(other):
            raise TypeError('can only subtract SIPCounter from another SIPCounter')
        sip_filter = self.sip_filter - other.sip_filter
        host_filter = self.host_filter - other.host_filter
        known_servers = self.known_servers - other.known_servers
        known_ports = self.known_ports - other.known_ports
        name = ' '.join(x for x in self.name.split() if x != other.name)
        dup = deepcopy(self._data)
        self.update(other, subtract=True)
        new = deepcopy(self._data)
        self._data = dup
        return SIPCounter(sip_filte=sip_filter,
                          host_filter=host_filter,
                          known_servers=known_servers,
                          known_ports=known_ports,
                          name=name,
                          data=new)

    def __iadd__(self, other):
        if type(self) != type(other):
            raise TypeError('can only add to SIPCounter another SIPCounter')
        self.sip_filter = self.sip_filter | other.sip_filter
        self.reSIPFilter = re.compile(r'(%s)' % '|'.join(self.sip_filter))
        self.host_filter = self.host_filter | other.host_filter
        self.known_servers = self.known_servers | other.known_servers
        self.known_ports = self.known_ports | other.known_ports
        self.name = ' '.join((self.name, other.name))
        self.update(other.data)

    def __isub__(self, other):
        if type(self) != type(other):
            raise TypeError('can only subtract from a SIPCounter another SIPCounter')
        self.sip_filter = self.sip_filter - other.sip_filter
        self.reSIPFilter = re.compile(r'(%s)' % '|'.join(self.sip_filter))
        self.host_filter = self.host_filter - other.host_filter
        self.known_servers = self.known_servers - other.known_servers
        self.known_ports = self.known_ports - other.known_ports
        self.name = ' '.join(x for x in self.name.split() if x != other.name)
        self.update(other, subtract=True)

    def __lt__(self, other):
        return self.total < other.total

    def __gt__(self, other):
        return self.total > other.total

    def __ge__(self, other):
        return self.total >= other.total

    def __le__(self, other):
        return self.total <= other.total

    def __eq__(self, other):
        return self.total == other.total

    def __ne__(self, other):
        return self.total != other.total

    def __repr__(self):
        s = "SIPCounter(name='%s', sip_filter=%s, host_filter=%s, known_servers=%s, known_ports=%s, data=%s)"
        return s % (self.name,
                    self.sip_filter,
                    self.host_filter,
                    self.known_servers,
                    self.known_ports,
                    self._data)

    def __str__(self):
        return '<%s instance at %s>' % (self.__class__.__name__, id(self))

if __name__ == '__main__':
    import random
    d = {('1.1.1.1', '2.2.2.2', 'TLS', '5061', '33332'): {'->': Counter(), '<-': Counter()},
         ('1.1.1.1', '2.2.2.2', 'TLS', '5061', '33333'): {'->': Counter(), '<-': Counter()},
         ('1.1.1.1', '2.2.2.2', 'TCP', '5060', '33334'): {'->': Counter(), '<-': Counter()},
         ('1.1.1.1', '2.2.2.2', 'TCP', '5062', '33335'): {'->': Counter(), '<-': Counter()},
         ('1.1.1.1', '3.3.3.3', 'TCP', '5060', '33336'): {'->': Counter(), '<-': Counter()},
         ('1.1.1.1', '3.3.3.3', 'UDP', '5060', '33337'): {'->': Counter(), '<-': Counter()}}
    d[('1.1.1.1', '2.2.2.2', 'TLS', '5061', '33332')]['->'].update(
        ('REGISTER' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '2.2.2.2', 'TLS', '5061', '33333')]['->'].update(
        ('INVITE' for x in xrange(random.randrange(0, 2000))))
    d[('1.1.1.1', '2.2.2.2', 'TLS', '5061', '33332')]['<-'].update(
        ('100' for x in xrange(random.randrange(0, 2000))))
    d[('1.1.1.1', '2.2.2.2', 'TLS', '5061', '33333')]['<-'].update(
        ('200' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '2.2.2.2', 'TCP', '5060', '33334')]['->'].update(
        ('REGISTER' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '2.2.2.2', 'TCP', '5062', '33335')]['->'].update(
        ('REFER' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '2.2.2.2', 'TCP', '5060', '33334')]['<-'].update(
        ('100' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '2.2.2.2', 'TCP', '5062', '33335')]['<-'].update(
        ('202' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '3.3.3.3', 'TCP', '5060', '33336')]['<-'].update(
        ('REFER' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '3.3.3.3', 'TCP', '5060', '33336')]['->'].update(
        ('202' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '3.3.3.3', 'UDP', '5060', '33337')]['->'].update(
        ('INVITE' for x in xrange(random.randrange(0, 1000))))
    d[('1.1.1.1', '3.3.3.3', 'UDP', '5060', '33337')]['<-'].update(
        ('200' for x in xrange(random.randrange(0, 1000))))
    d2 = {('', '', '', '',): {'<>': Counter()}}
    d2[('', '', '', '')]['<>'].update(
        ('INVITE' for x in xrange(random.randrange(0, 2000))))
    d2[('', '', '', '')]['<>'].update(
        ('PUBLISH' for x in xrange(random.randrange(0, 2000))))
    d2[('', '', '', '')]['<>'].update(
        ('CANCEL' for x in xrange(random.randrange(0, 10))))
    d2[('', '', '', '')]['<>'].update(
        ('100' for x in xrange(random.randrange(0, 2000))))
    d2[('', '', '', '')]['<>'].update(
        ('200' for x in xrange(random.randrange(0, 20000))))
    d2[('', '', '', '')]['<>'].update(
        ('180' for x in xrange(random.randrange(0, 2000))))
    sipcounter = SIPCounter(data=d, name='Switch-A')
    sipcounter2 = SIPCounter(data=d2, name='Switch-B')
    print sipcounter.pprint(depth=4, summary=True, header=True)
    print sipcounter2.pprint(summary=False)
