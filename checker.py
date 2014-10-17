#!/usr/bin/python

import rrdtool
import netsnmp
from utils import _slugify as slug
import time
import math
import numpy
import memcache
import detection
from settings import *
memc = memcache.Client(['127.0.0.1:11211'])

import telnetlib
from socket import error as SocketError
def get_top_talkers():
    try:
        fc = telnetlib.Telnet(NFDUMP_HOST, NFDUMP_PORT, NFDUMP_TIMEOUT)
        toptalkers = fc.read_all()
        fc.close()
    except SocketError:
        toptalkers = ''
        pass
    return toptalkers

import smtplib

def draw_graph(ifce):
    graph_slug = ifce['slug']
    graph_type = ifce['type']
    graph_title = "%s:%s:%s"%(graph_type, ifce['name'], ifce['host'])
    graph_ds = GRAPH_TYPES[graph_type]
    graph_legends = GRAPH_TITLES[graph_type]
    graph_options = GRAPH_OPTIONS[graph_type]
    graph_colors = GRAPH_COLORS[graph_type]
    graph_multipliers = GRAPH_CDEF_MULTIPLIERS[graph_type]
    rrdpath = "%s/%s.rrd" %(RRD_LOCATION, graph_slug)
    imgpath = "%s/%s.png" %(RRD_LOCATION, graph_slug)
    graph_args = [str("%s" %imgpath), "--start", "-3h", "--width", "800", "--height", "600", "-t", "%s"%graph_title]
    for i, gds in enumerate(graph_ds):
        graph_args.append(str("DEF:ds%s=%s:ds%s:AVERAGE"%(gds,rrdpath,i)))
    for i, gds in enumerate(graph_ds):
        graph_args.append(str("CDEF:%s=ds%s,%s,*"%(gds,gds,graph_multipliers[i])))
    for i, gds in enumerate(graph_ds):
        graph_args.append(str("%s:%s%s:%s"%(graph_options[i], gds ,graph_colors[i], graph_legends[i])))
    graph_args[-1] = "%s\\r"%graph_args[-1]
    args=[str(val) for val in graph_args]
    print args
    return rrdtool.graphv(*args)

# Import the email modules we'll need
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart

def notify(img = None, ifce = None):
    msgtxt = 'Possible network anomaly'
    ifcename = ifce['name']
    ifcehost = ifce['host']
    ifceslug = ifce['slug']
    ifcetype = ifce['type']
    ifcecontacts = ifce['NOTIFY']
    if NFDUMP_ENABLE:
        toptalkers = get_top_talkers()
        if toptalkers:
            msgtxt += '\n\n'
            msgtxt += toptalkers
    msgtxt = MIMEText(msgtxt)
    msg = MIMEMultipart()
    msg['Subject'] = 'Possible network anomaly detected at %s %s - %s' %(ifcetype, ifcename, ifcehost)
    if img:
        try:
            fp = open(img, 'rb')
            img = MIMEImage(fp.read())
            fp.close()
            img.add_header('Content-Disposition', 'attachment', filename='%s.png' %(ifceslug))
            msg.attach(img)
        except:
            pass
    msg.attach(msgtxt)
    s = smtplib.SMTP('localhost')
    s.sendmail(MAIL_FROM, ifcecontacts, msg.as_string())
    s.quit()
    return

def check_and_mail(ifce):
    graph_slug = ifce['slug']
    detection_algo = ifce['DETECTION_ALGO']
    rrdpath = "%s/%s.rrd" %(RRD_LOCATION, graph_slug)
    imgpath = "%s/%s.png" %(RRD_LOCATION, graph_slug)
    attack_check = getattr(detection, "%s_algo" %(detection_algo))
    ds0An, ds1An = attack_check(rrdpath, ifce)
    if ds0An or ds1An:
        cached_anomaly = memc.get(str('%s_error')%(graph_slug))
        if cached_anomaly is None:
            memc.set(str('%s_error')%(graph_slug), '1', MEMCACHE_TIMEOUT)
            notify(imgpath, ifce)
    return

def graphall():
    for ifce in MONITORED_IFCES:
        draw_graph(ifce)
        check_and_mail(ifce)
    return

if __name__ == "__main__":
    graphall()


