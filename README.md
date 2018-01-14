# sipcounter
Implements a simple SIP message counter with optional direction, source/destination IP, protocol and port tracking.
It is meant to be used to count the SIP requests and responses per link. A link is comprised of the source and
destination host IP addresses, the transport protocol type (TLS, TCP, UDP) and the ports. The internal self._data
dictionary may be printed out using the 'pprint' convenience method or processed through other means before 
clearing the counters and starting to count all over again.

### Example ###
To count only INVITE and ReINVITE messages and their corresponding errors reponses (4xx, 5xx, 6xx):

```
from sipcounter import SIPCounter

sipcounter = SIPCounter(
                    name='SBCE Cone-A',
                    sip_filter=set(['INVITE', 'ReINVITE', '4', '5', '6']))
    while True:
        try:
            # 'reader' is log parser generator
            stamp, sipmsg, msgdir, srcip, srcport, dstip, dstport = reader.next()
            sipcounter.add(sipmsg, msgdir, srcip, srcport, dstip, dstport)
        except:
            print(sipcounter.pprint(title='2018-0101 01:01:00'))
            break
```

This will yield something like:

```
    2018-0101 01:01:00          INVITE   ReINVITE    503       600
    SBCE Cone-A               ---> <--- ---> <--- ---> <--- ---> <---
    1.1.1.1-tcp-5060-2.2.2.1    13   10   40   40    0    0    0    0
    1.1.1.1-tls-5061-2.2.2.1    13   10   36   42    1    0    1    0
    SUMMARY                     26   20   76   82    1    0    1    0
```

### Example ###

Another example would be to capture the messages on the wire with tshark.

```
import time
from subprocess import Popen, PIPE
from sipcounter import SIPCounter

sipcounter = SIPCounter(name='Localhost')
cmd = ['tshark', '-l', '-n', '-i', 'any', 'tcp', '-R', 'sip',
       '-E', 'separator=|', '-T', 'fields',
       '-e', 'ip.src', '-e', 'tcp.srcport',
       '-e', 'ip.dst', '-e', 'tcp.dstport',
       '-e', 'sip.Request-Line', '-e', 'sip.Status-Line',
       '-e', 'sip.CSeq', '-e', 'sip.To', '-e', 'sip.Via']

p = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE)
while True:
    try:
        output = p.stdout.readline()
        if output:
            srcip, srcport, dstip, dstport, sipmsg = output.split('|', 4)
            z = zip(('', 'CSeq: ', 'To: ', 'Via: '),
                    (x for x in sipmsg.split('|') if x))
            sipmsg = '\r\n'.join((''.join(x) for x in z))
            sipcounter.add(sipmsg, None, srcip, srcport, dstip, dstport)
        elif output == '' and p.poll() is not None:
            break
        else:
            time.sleep(0.1)
    except KeyboardInterrupt:
        p.terminate()
        p.wait()
        break

print(sipcounter.pprint(title=time.strftime('%Y-%m-%d %H:%M:%S')))
```

With a possible output below upon CTRL^C:

```
2018-01-14 16:01:10         INVITE   ReINVITE    BYE      CANCEL     500       503       600   
Localhost                 ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- 
1.1.1.1-tcp-5060-2.2.2.1    43   59  196  166  109  128  123  107  142  150  127  146  142  146
1.1.1.1-tls-5061-2.2.2.1    75   65  156  175  100  124  114   96  171  153  154  145  156  142
1.1.1.1-tcp-5060-2.2.2.2    36   20   82   91   49   67   63   66   82   71   67   88   57   72
1.1.1.1-tls-5061-2.2.2.2    30   35   85   91   64   57   54   49   91   73   81   62   90   89
1.1.1.1-tcp-5060-2.2.2.3    31   34   96   97   56   49   54   60   74   80   81   66   78   75
1.1.1.1-tls-5061-2.2.2.3    29   37   81  101   55   48   41   60   91   70   62   63   77   81
1.1.1.2-tcp-5060-2.2.2.1    59   64  156  164  101  113  101  124  145  152  157  169  133  165
1.1.1.2-tcp-5062-2.2.2.1    48   61  164  169  111  100  124   98  147  151  153  141  149  148
1.1.1.2-udp-5060-2.2.2.1    59   52  141  167  110  104  110  132  147  152  145  148  161  157
1.1.1.2-tcp-5060-2.2.2.2    24   26   79   91   51   44   61   52   71   91   85   63   75   74
1.1.1.2-tcp-5062-2.2.2.2    32   37   83   98   62   66   59   47   68   68   60   76   67   77
1.1.1.2-udp-5060-2.2.2.2    25   28   73   81   47   61   70   59   96   76   88   68   74   69
1.1.1.2-tcp-5060-2.2.2.3    27   19   69   81   57   48   55   74   85   93   68   72   61   70
1.1.1.2-tcp-5062-2.2.2.3    28   31   79   87   55   55   59   56   89   74   58   78   74   78
1.1.1.2-udp-5060-2.2.2.3    29   27   79   80   61   47   51   54   70   70   73   86   67   73
SUMMARY                    575  595 1619 1739 1088 1111 1139 1134 1569 1524 1459 1471 1461 1516
```
