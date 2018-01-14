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

Another example would be to capture the messages on the wire with tshark and print out the top 3 
busiest links (most total amount of messages) and the summary.

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

print(sipcounter.pprint(title='Top 3', data=sipcounter.most_common(3, depth=2))
```

With a possible output below upon CTRL^C:

```
Top 3                    INVITE   ReINVITE    BYE      CANCEL     500       503       600   
SIP Server 1.1.1.{1,2} ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- ---> <--- 
1.1.1.2-2.2.2.1         175  171  507  513  354  343  323  326  459  452  428  461  447  441
1.1.1.1-2.2.2.1         113   95  341  359  240  212  233  219  309  278  296  284  312  295
1.1.1.2-2.2.2.2          84   93  253  252  169  190  163  161  255  234  215  222  231  224
SUMMARY                 372  359 1101 1124  763  745  719  706 1023  964  939  967  990  960
```
