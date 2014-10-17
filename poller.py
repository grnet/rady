#!/usr/bin/python

import rrdtool
import netsnmp
from utils import _slugify as slug
import time
from settings import *

def poll_ifce(ifce):
    ifIndex = ifce['ifIndex']
    host = ifce['host']
    version = ifce['SNMP_VERSION']
    community = ifce['SNMP_COMMUNITY']
    ds = []
    for i, oid in enumerate(GRAPH_TYPES[ifce['type']]):
        snmpbind = netsnmp.Varbind('%s.%s'%(oid,ifIndex))
        result = netsnmp.snmpget(snmpbind, Version=version, DestHost='%s'%host, Community='%s'%community)[0]
        ds.append(result)
    return ds

def graph_ifce(ifce):
    graph_slug = ifce['slug']
    host = ifce['host']
    type = ifce['type']
    rrdpath = "%s/%s.rrd" %(RRD_LOCATION, graph_slug)
    try:
        gf = open(rrdpath)
    except:
        gf = rrdtool.create(str(rrdpath), str("--start"), str(1349965501), str("--step"), str(STEP), [str('DS:ds0:COUNTER:%s:U:U'%HEARTBEAT), str('DS:ds1:COUNTER:%s:U:U'%HEARTBEAT)], str('RRA:AVERAGE:0.5:1:2880'))
    values = poll_ifce(ifce)
    rrdtool.update(
            str(rrdpath), 
            str('--template'), str('ds0:ds1'),
            str("%s"%int(time.time())+":" +values[0]+":"+values[1]))

def graphall():
    for ifce in MONITORED_IFCES:
        graph_ifce(ifce)
    return

if __name__ == "__main__":
    graphall()

