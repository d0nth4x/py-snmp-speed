from pysnmp.hlapi import *
from binascii import hexlify
from struct import unpack
from pprint import pprint


class Snmpv2:

    def __init__(self, community, host, port=161):

        self.community = community
        self.host = host
        self.port = port

    def walk(self, oid, hex=False):
        returnArray = {}

        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in nextCmd(SnmpEngine(),
                                  CommunityData(self.community),
                                  UdpTransportTarget((self.host, self.port)),
                                  ContextData(),
                                  ObjectType(ObjectIdentity(oid)),
                                  lexicographicMode=False):

            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for oid, val in varBinds:
                    if hex:
                        returnArray[oid.prettyPrint()] = val.prettyPrint()
                        if len(val.prettyPrint()) == 8:
                            val = hexlify(val.prettyPrint())
                        else:
                            val = val.prettyPrint().replace(str('0x'), '')

                        returnArray[oid.prettyPrint()] = val
                    else:
                        returnArray[oid.prettyPrint()] = val.prettyPrint()

        return returnArray


    def getAllOnt(self,index):

        descs = {}
        softs = {}
        ifNames = {}
        returnArray = []

        oids = {
            'ifName': ('1.3.6.1.2.1.31.1.1.1.1'),
            'desc': ('1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9'),
            'soft': ('1.3.6.1.4.1.2011.6.128.1.1.2.45.1.5'),
            'serial': ('1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3')
        }

        result = self.walk(oid=oids['ifName'], hex=False)
        for key, val in result.iteritems():
            key = key.split('.')
            ifNames.update({key[-1]: val})

        for key, val in ifNames.iteritems():
            descs.update({key: dict()})
            softs.update({key: dict()})

        result = self.walk(oid=oids['desc'], hex=False)
        for key, val in result.iteritems():
            key = key.split('.')
            descs[key[-2]][key[-1]] = val

        result = self.walk(oid=oids['soft'], hex=False)
        for key, val in result.iteritems():
            key = key.split('.')
            softs[key[-2]][key[-1]] = val

        result = self.walk(oid=oids['serial'], hex=True)
        for key, val in result.iteritems():
            serialPath = key.split('.')

            returnArray.append({
                'index': index,
                'snmpIf': serialPath[-2],
                'port': ifNames[serialPath[-2]],
                'ontId': serialPath[-1],
                'desc': descs[serialPath[-2]][serialPath[-1]],
                'sn': val.upper(),
                'soft': softs[serialPath[-2]][serialPath[-1]]
            })

        return returnArray
