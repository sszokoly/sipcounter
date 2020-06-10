#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from subprocess import Popen, PIPE
from sipcounter import SIPCounter
import time

c = SIPCounter(name="example")
cmd = [
    "tshark",
    "-l",
    "-n",
    "-i",
    "any",
    "-Y", 
    "sip",
    "-E",
    "separator=|",
    "-T",
    "fields",
    "-e",
    "ip.src",
    "-e",
    "tcp.srcport",
    "-e",
    "ip.dst",
    "-e",
    "tcp.dstport",
    "-e",
    "sip.Request-Line",
    "-e",
    "sip.Status-Line",
    "-e",
    "sip.CSeq",
    "-e",
    "sip.To",
    "-e",
    "sip.Via",
]

n = 0
p = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE)
while True:
    try:
        output = p.stdout.readline().decode("ascii")
        if output:
            srcip, srcport, dstip, dstport, sipmsg = output.split("|", 4)
            z = zip(("", "CSeq: ", "To: ", "Via: "),
                    (x for x in sipmsg.split("|") if x))
            sipmsg = "\r\n".join(("".join(x) for x in z))
            n += c.add(sipmsg, None, srcip, srcport, dstip, dstport)
            print(n, end="\r")
        elif output == "" and p.poll() is not None:
            break
        else:
            time.sleep(0.1)
    except KeyboardInterrupt:
        p.terminate()
        p.wait()
        break

print(end="\r")
print(c.tostring(title=time.strftime("%Y-%m-%d %H:%M:%S")))
