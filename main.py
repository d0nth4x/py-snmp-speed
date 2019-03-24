from pysnmp.hlapi import *
from time import time, sleep
from snmpfunctions import Snmpv2


if __name__ == '__main__':

    snmp = Snmpv2(host='172.0.0.1', community='public')
    for x in range(0, 30):
        time1 = int(time())
        walk1 = snmp.walk('1.3.6.1.2.1.31.1.1.1.6')['SNMPv2-SMI::mib-2.31.1.1.1.6.7']
        sleep(2)
        time2 = int(time())
        timec = time2 - time1
        for x in walk1:
            print (int(x) * 800) / ((timec) * 1250000000)
            
