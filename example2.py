import datetime
import time
from subprocess import Popen, PIPE
from SIPCounter import SIPCounter

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
print(sipcounter.pprint(title=time.strftime("%Y-%m-%d %H:%M:%S")))

#2018-01-12 13:58:48                   OPTIONS   403
#Localhost                             --> <-- --> <--
#10.130.93.132-tcp-5060-10.130.93.144    0   3   3   0
#SUMMARY                                 0   3   3   0
