import re
from collections import defaultdict, Counter, OrderedDict
from copy import deepcopy
from itertools import chain
from operator import itemgetter

class SIPCounter(object):
    """
    Implements a simple SIP message counter with optional direction,
    source/destination IP, protocol and port tracking. It is meant
    to be used to count the SIP requests and responses only per link.
    A link is comprised of the source/destination host IP address,
    the transport protocol type (TLS, TCP, UDP) and the ports. It can
    filter and count only certian type of SIP messages, for instance
    one might wish to monitor only the INVITE and ReINVITE requests
    and any corresponding error messages, see example below. The
    internal self._data storage may be printed out using the 'pprint'
    convenience method or processed through other means before
    clearing the counters and starting to count all over again.

    To count only INVITE and ReINVITE messages and their corresponding
    errors reponses (4xx, 5xx, 6xx) create an instance as follows:

    sipcounter = SIPCounter(
                    name='SBCE Cone-A',
                    sip_filter=set(['INVITE','ReINVITE','4','5','6']),
                           )
    while 1:
        try:
            stamp, sipmsg, msgdir, srcip, srcport, dstip, dstport = sip.next()
            sipcounter.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)
        except:
            print sipcounter.pprint(title='2018-0101 01:01:00')
            break

    This will yield something like this:

    2018-0101 01:01:00          INVITE   ReINVITE    503       600
    SBCE Cone-A               ---> <--- ---> <--- ---> <--- ---> <---
    1.1.1.1-tcp-5060-2.2.2.1    13   10   40   40    0    0    0    0
    1.1.1.1-tls-5061-2.2.2.1    13   10   36   42    1    0    1    0
    SUMMARY                     26   20   76   82    1    0    1    0

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
        Initializes a SIPCounter instance with optional arguments.
        The following keyword argument are available:

        sip_filter: serves as a SIP message count filter, out of which
                    is built a regex object which is used to match the
                    request methods of interest and the corresponding
                    responses. If not provided a default '.*' pattern
                    is used which will match all requests and responses.
                    For example to count only INVITE and ReINVITE
                    messages and any error responses for these requests
                    one should pass the following set:

                    sip_filter=set(['INVITE', 'ReINVITE', '4', '5', '6'])

                    It is also possible to be more specific. For example:

                    sip_filter=set(['INVITE', 'ReINVITE', '408', '503'])

        host_filter: serves as a host capture filter, if the source and
                    destination IP address is provided a SIP message will
                    only be counted if either the origin (srcip) or the
                    recipient (dstip) of the message is in this set.
                    For example:

                    host_filter=set(['1.1.1.1', '2.2.2.2', '3.3.3.3'])

        known_servers: the internal logic of this class tries to guess
                    the Server (or Local) and the Client (or Remote) side
                    when processing a SIP message based on the received
                    message direction (msgdir) or port numbers (srcport,
                    dstport) when these arguments are provided. If this
                    logic fails to determine correctly the role of the
                    communicating parties then the data may end up being
                    counted under a new link as opposed to an already
                    existing link or a link (dictionary key) will be
                    created with order swopped. This argument serves as
                    a helper to the internal logic and takes precedence
                    over the srcport/dstport arguments. For example:

                    known_servers=set(['1.1.1.2', '1.1.1.1'])

        known_ports: this is yet another helper set to the internal logic
                    to help determine which of the two communicating
                    parties may be the Server (or Local) side and which
                    the Client (or Remote) side. This may only be required
                    if the SIP service is not running on the well-known
                    SIP ports which are port 5060 or 5061. For example:

                    known_ports=set(['5070', '5080'])

        data:       In rare situations there may be a need to initialize
                    an instance with some data (default counts) prior to
                    incrementing the counters through the 'update' or
                    'add' methods. This argument has to have the same
                    format as the internal self._data storeage.

                    {('<server ip>',    # tuple of strings as key
                      '<client ip>',
                      '<protocol>',
                      '<service port>',
                      '<client port>') :
                      {'msgdir' : Counter(     # dictionary as value
                                    {'<sip message type>' : int,
                                    '<sip message type>' : int,
                                    ...})
                      }, ...}

                    For example to initialize an instance with some data:

                    data={('1.1.1.1', '2.2.2.2', 'tcp', '5060', '34556'):
                    {'<-': Counter({'INVITE': 1, 'ReINVITE': 1}),
                     '->': Counter({'200': 1, '100': 1})}}

        name:       the name of the class instance, for example it can
                    store the name of the host where the SIP messages
                    are captured or the timestamp of when the instance
                    was created or cleared last time.

        :param      sip_filter: (set) SIP message capture filter
                    host_filter: (set) SIP host capture filter
                    known_servers: (set) known SIP servers/proxies
                    known_ports: (set) known SIP services ports
                                 excluding 5060, 5061
                    data: (dict) to prepopulate self._data
                    name: (string) name of the instance
        """
        self.sip_filter = kwargs.get('sip_filter', set(['.*']))
        self.host_filter = kwargs.get('host_filter', set())
        self.known_servers = kwargs.get('known_servers', set())
        self.known_ports = kwargs.get('known_ports', set())
        self._data = kwargs.get('data', {})
        self.name = kwargs.get('name', '')
        self.dirIn = '<-'
        self.dirOut = '->'
        self.dirBoth = '<>'
        self.local = 'local'
        self.remote = 'remote'
        self.known_ports = self.known_ports | set(['5060', '5061'])
        self.reSIPFilter = re.compile(r'(%s)' % '|'.join(self.sip_filter))
        self.reReINVITE = re.compile(r'(To:|t:) .*(tag=)', re.MULTILINE)
        self.reCSeq = re.compile(r'CSeq: \d+ (\w+)', re.MULTILINE)
        self.reVia = re.compile(r'(Via:|v:) SIP/2.0/(.*) ', re.MULTILINE)

    @property
    def data(self):
        return self._data

    @property
    def total(self):
        """
        Sums up all the Counter() objects found in self._data.
        :return: int
        """
        return sum(z for x in self._data.values()
                     for y in x.values()
                     for z in y.values())

    def add(self, sipmsg, msgdir=None, *args):
        """
        :param sipmsg: (string) the SIP message body
        :param msgdir: (string) determines the direction of
                        the message and consequently the order in which
                        the communicating parties are placed into the
                        self._data dictionary as key. The direction can
                        be 'IN' for incoming or else for outgoing.
        :param args:   (tuple of strings) contains the details of the
                        communicating parties in the order shown below:

                        (srcip, srcport, dstip, dstport, [proto])

                        the [proto]col is optional, if not provided it
                        will be extracted from the top Via header.

                        For example both are valid for args:

                        ('1.1.1.1', '5060', '2.2.2.2', '34556', 'TCP')
                        ('1.1.1.1', '5060', '2.2.2.2', '34556')

                        In the example above since the srcport is a
                        well-known SIP service port and the other is not
                        and the known_servers set also does not indicate
                        neither IP address to be a server, furthermore
                        the known_ports set also does not dictate
                        otherwise the SIP message will be counted
                        towards the link placed into self._data as a key
                        as follows:

                        ('1.1.1.1', '2.2.2.2', 'tcp', '5060', '34556')

                        Any further messages between these two entities
                        using parameters listed in the tuple above will
                        be counted under the same key.
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
            method = m.group(1)
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
        # Determining server/client side
        if args:
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
        else:
            link = [self.local, self.remote]
            service_port, client_port = '', ''
        # Determining protocol
        if proto:
            proto = proto[0]
        else:
            m = self.reVia.search(sipmsg)
            if m:
                proto = m.group(2)
            else:
                proto = 'udp'
        link.extend([proto.lower(), service_port, client_port])
        if self.reSIPFilter.match(method) and self.reSIPFilter.match(msgtype):
            self._data.setdefault(tuple(link), {}
                     ).setdefault(msgdir, Counter()
                     ).update([msgtype])

    def update(self, iterable, subtract=False):
        """
        Updates the internal Counters. Other methods use this too.
        It is unlikely to be used often directly by the consumer of
        this class.
        :param iterable: (dict) of the same type as the self._data,
                         it's primary purpose is to allow access to
                         the internal collections.Counters in order
                         to  update their values. For example:

                         {('1.1.1.1', '2.2.2.2', 'tcp', '5060', '34556'):
                         {'<-': Counter({'UPDATE': 1, 'ReINVITE': 1}),
                         '->': Counter({'200': 1, '100': 1})}}

        :param subtract: (bool) if the internal Counter is to be
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
        Clears the self._data dictionary. This can be used when for
        example a new sampling period begins and the counting needs
        to start from zero.
        :return: None
        """
        self._data.clear()

    def iteritems(self):
        """
        Returns the key,value pairs of the self._data dictionary.
        :return: (iterator)
        """
        return self._data.iteritems()

    def iterkeys(self):
        """
        Returns the keys (aka links) of the self._data dictionary.
        :return: (iterator)
        """
        return self._data.iterkeys()

    def keys(self):
        """
        Provides the list of internal storage keys (aka links) sorted
                 by Server/Proxy IP, then Client IP, then protocol,
                 followed by Server side port and Client side port.
        :return: (list)
        """
        return sorted(self._data.iterkeys(), key=itemgetter(0, 1, 2, 3))

    def groupby(self, depth=4):
        """
        This method has two purposes. One is to group (or add) together
        the Counters of links depending on how deep the caller looks
        into the self._data keys. The other is to order the grouped
        dictionary elems. Let's assume there are five separate links in
        the self._data as follows:

        {('1.1.1.1', '2.2.2.2', 'tcp', '5060', '33332'):  {'<-': Counter({'INVITE': 1})},
         ('1.1.1.1', '2.2.2.2', 'tcp', '5060', '33333'):  {'<-': Counter({'INVITE': 1})},
         ('1.1.1.1', '3.3.3.3', 'tcp', '5060', '33334'):  {'<-': Counter({'INVITE': 1})},
         ('1.1.1.1', '2.2.2.2', 'tcp', '5062', '33335'):  {'<-': Counter({'INVITE': 1})},
         ('1.1.1.1', '2.2.2.2', 'tls', '5061', '33336'):  {'<-': Counter({'INVITE': 1})}}

        Calling groupby(depth=5) would only sort and so return an
        OrderedDict placing the Counters between '1.1.1.1' and '2.2.2.2'
        first before that of '1.1.1.1' and '3.3.3.3'.
        Calling groupby(depth=4) would not only sort the links but also
        merge the Counters of '1.1.1.1' and '2.2.2.2' over 'tcp', port
        '5060' ignoring the client side ports used ('33332' and '33333').

        OrderedDict([.....
        ('1.1.1.1', '2.2.2.2', 'tcp', '5060'):  {'<-': Counter({'INVITE': 2})},
        ('1.1.1.1', '2.2.2.2', 'tcp', '5062'):  {'<-': Counter({'INVITE': 1})},
        ('1.1.1.1', '2.2.2.2', 'tls', '5061'):  {'<-': Counter({'INVITE': 1})},
        ('1.1.1.1', '3.3.3.3', 'tcp', '5060'):  {'<-': Counter({'INVITE': 1})},
        ...])

        Calling groupby(depth=3) would order and merge the Counters of
        '1.1.1.1' and '2.2.2.2' over 'tcp' regardless of the server
        or client side ports used.

        OrderedDict([.....
        ('1.1.1.1', '2.2.2.2', 'tcp'), {'<-': Counter({'INVITE': 3})}),
        ('1.1.1.1', '2.2.2.2', 'tls'), {'<-': Counter({'INVITE': 1})}),
        ('1.1.1.1', '3.3.3.3', 'tcp'), {'<-': Counter({'INVITE': 1})}),
        ...])

        Calling groupby(depth=2) would merge even further the Counters
        in addition to sorting them:

        OrderedDict([.....
        ('1.1.1.1', '2.2.2.2'), {'<-': Counter({'INVITE': 4})}),
        ('1.1.1.1', '3.3.3.3'), {'<-': Counter({'INVITE': 1})}),
        ...])

        And so on.

        :param depth: (int) indicating how deep into the key, which is
        a tuple of potentially five strings, the method should look
        into when grouping the Counters together.
        :return (OrderedDict) grouped and ordered by Server, Client
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
                        g.setdefault(link[0:depth], {}
                        ).setdefault(k, Counter()
                        ).update(self._data[link][k])
        l = sorted(g.iterkeys(), key=depth and itemgetter(*range(0, depth)) or None)
        return OrderedDict((k, g[k]) for k in l)

    def most_common(self, n=None, depth=4):
        """
        Returns an OrderedDict of the n busiest links in descending
        order. Optionally it groups (merged) links depending on how
        many elements of the key is to be considered significant.
        :param n: (int) how many of the busiest links to return
        :param depth: (int) indicating how deep into the key, which is
                      a tuple of potentially five strings, the method
                      should look into when grouping the Counters together.
        :return: (OrderedDict) grouped and ordered by Server, Client and
                 protocol.
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
        Returns a dictionary with the summary of all Counters per SIP
        message type captured in the self._data or in the optional
        self._data like 'data' dictionary.
        :param data: (dict) optional self._data like dictionary
        :param title: (string) optional key name of the dictionary
        :return: (dict) with the summary of all Counters.
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
        Returns a list of SIP message types found in self._data or in
        the optionally provided self._data like 'data' dictionary.
        :param data: (dict) optional self._data like dictionary
        :return: (list) list of strings of all the SIP message types
        """
        if data is None:
            data = self._data
        s = set(x for s in data.values() for y in s.values() for x in y)
        requests = sorted((x for x in s if not x.isdigit()),
                   key=lambda x: self.SORT_ORDER.get(x, len(self.SORT_ORDER)))
        responses = sorted((x for x in s if x.isdigit()))
        return requests + responses

    def pprint(self, depth=4, title='', header=True, links=True, summary=True,
                     data=None):
        """
        Convenience method to provide a basic readable output of the
        self._data dictionary. The representation of the self._data is
        subjective, therefore the primary objective of this method was
        to provide a, example. Consumers are encouraged to write their
        own functions to present the content of the self._data the way
        that best suits their needs.
        :param depth: (int) indicating how deep into the key, which is
                      a tuple of potentially four strings, the method
                      should look into when grouping the Counters.
        :param title: (string) optional information to print inline
                      with top line, for example a timestamp
        :param header: (bool) if the header is to be printed
        :param links: (bool) if the individual links are to be printed
        :param summary: (bool) if summary line is to be printed
        :param data: (dict) optional self._data like dictionary, this
                     may be used more often. For example to pprint the
                     busiest 5 links:

                     print sipcounter.pprint(data=sipcounter.most_common(n=5))

        :return: (string) a ready to be printed representation of self._data
        """
        output = []
        if data is None:
            data = self.groupby(depth=depth)
        if not data:
            return ''
        elif summary:
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
        link_width = max(ll, len(self.name), sl, len(title)) + 1
        if header:
            output.append('')
            columns = ' '.join(x.center(column_width) for x in elements)
            output.append(title.ljust(link_width) + columns)
            if directions > 1:
                output.append(''.join((
                    self.name.ljust(link_width),
                    len(elements) * (
                        ' '.join((
                        self.dirOut.rjust(column_width/directions, '-'),
                        self.dirIn.ljust(column_width/directions, '-')))
                        + ' ')
                            )))
            else:
                output.append(''.join((
                    self.name.ljust(link_width),
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
    d2 = {('', '', '', '', ''): {'<>': Counter()}}
    d2[('', '', '', '', '')]['<>'].update(
        ('INVITE' for x in xrange(random.randrange(0, 2000))))
    d2[('', '', '', '', '')]['<>'].update(
        ('PUBLISH' for x in xrange(random.randrange(0, 2000))))
    d2[('', '', '', '', '')]['<>'].update(
        ('CANCEL' for x in xrange(random.randrange(0, 10))))
    d2[('', '', '', '', '')]['<>'].update(
        ('100' for x in xrange(random.randrange(0, 2000))))
    d2[('', '', '', '', '')]['<>'].update(
        ('200' for x in xrange(random.randrange(0, 20000))))
    d2[('', '', '', '', '')]['<>'].update(
        ('180' for x in xrange(random.randrange(0, 2000))))
    sipcounter = SIPCounter(data=d, name='Switch-A')
    sipcounter2 = SIPCounter(data=d2, name='Switch-B')
    print(sipcounter.pprint(depth=4, summary=True, header=True, title='2018-0106 16:00:00'))
    print(sipcounter2.pprint(summary=False))
