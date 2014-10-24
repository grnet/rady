#!/usr/bin/python

import rrdtool
import netsnmp
from utils import _slugify as slug
from utils import invertHex
import datetime, time
import math
import numpy
import memcache
import detection
from settings import *
memc = memcache.Client(['%s:%s'%(MEMCACHE_SERVER_ADDR, MEMCACHE_SERVER_PORT)])

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

def draw_graph(ifce, timestamp):
    graph_slug = ifce['slug']
    graph_type = ifce['type']
    graph_title = "%s:%s:%s"%(graph_type, ifce['name'], ifce['host'])
    graph_subtitle = "algorithm:%s threshold:%s "%(ifce['DETECTION_ALGO'], "%s" %(100*ifce['THRESHOLD']))+"%"
    graph_time = "%s" %timestamp
    tool_version = VERSION
    graph_time_timestamp = "%s" %int(time.mktime(timestamp.timetuple()))
    graph_ds = GRAPH_TYPES[graph_type]
    graph_legends = GRAPH_TITLES[graph_type]
    graph_options = GRAPH_OPTIONS[graph_type]
    graph_colors = GRAPH_COLORS[graph_type]
    vertical_legend = GRAPH_VERTICAL_LEGEND[graph_type]
    graph_multipliers = GRAPH_CDEF_MULTIPLIERS[graph_type]
    rrdpath = "%s/%s.rrd" %(RRD_LOCATION, graph_slug)
    imgpath = "%s/%s_%s.png" %(RRD_LOCATION, graph_slug, graph_time_timestamp)
    graph_args = [str("%s" %imgpath),
                  "--start", "-3h",
                  "--width", "800",
                  "--height", "600", 
                  "-t", "%s\n<span size='x-small'>%s</span>"%(graph_title,graph_subtitle),
                  "--pango-markup",
                  "--vertical-label", "%s"%vertical_legend,
                  "--watermark", "%s - rady %s" %(graph_time, tool_version),
                  ]
    for i, gds in enumerate(graph_ds):
        graph_args.append(str("DEF:ds%s=%s:ds%s:AVERAGE"%(gds,rrdpath,i)))
        if GRAPH_EMBED_AND_SHIFT:
            graph_args.append(str("DEF:last3hds%s=%s:ds%s:AVERAGE:end=now-3h:start=end-3h"%(gds,rrdpath,i)))
        graph_args.append(str("CDEF:%s=ds%s,%s,*"%(gds,gds,graph_multipliers[i])))
        if GRAPH_EMBED_AND_SHIFT:
            graph_args.append(str("CDEF:last3h%s=last3hds%s,%s,*"%(gds,gds,graph_multipliers[i])))
            graph_args.append(str("SHIFT:last3h%s:10800"%(gds)))
        graph_args.append(str("VDEF:max%s=%s,MAXIMUM"%(gds,gds)))
        if GRAPH_EMBED_AND_SHIFT:
            graph_args.append(str("%s:last3h%s%s:%s (3h ago)\\n"%(graph_options[i], gds ,invertHex(graph_colors[i])+"88", graph_legends[i])))
        graph_args.append(str("%s:%s%s:%s\\n"%(graph_options[i], gds ,graph_colors[i]+"dd", graph_legends[i])))
        
        gprint = "GPRINT:max%s" %gds + ":Max\:%8.2lf %s"
        graph_args.append(str("%s"%(gprint)))
        graph_args.append(str("GPRINT:max%s:" %gds +"at %c\\g:strftime"))
        graph_args.append(str("COMMENT:\\n"))
        if i == 0:
            dashline = "-"*120
            graph_args.append(str("COMMENT:%s\\n"%dashline))
    #graph_args[-1] = "%s\\r"%graph_args[-1]
    args=[str(val) for val in graph_args]
    return rrdtool.graphv(*args)

# Import the email modules we'll need
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart

def notify(imgpath = None, ifce = None):
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
    if imgpath:
        try:
            fp = open(imgpath, 'rb')
            img = MIMEImage(fp.read())
            fp.close()
            img.add_header('Content-Disposition', 'attachment', filename='%s' %(imgpath))
            msg.attach(img)
        except:
            pass
    msg.attach(msgtxt)
    s = smtplib.SMTP('localhost')
    s.sendmail(MAIL_FROM, ifcecontacts, msg.as_string())
    s.quit()
    return

def check_and_mail(ifce, timestamp):
    graph_slug = ifce['slug']
    detection_algo = ifce['DETECTION_ALGO']
    graph_time_timestamp = "%s" %int(time.mktime(timestamp.timetuple()))
    rrdpath = "%s/%s.rrd" %(RRD_LOCATION, graph_slug)
    imgpath = "%s/%s_%s.png" %(RRD_LOCATION, graph_slug, graph_time_timestamp)
    attack_check = getattr(detection, "%s_algo" %(detection_algo))
    ds0An, ds1An = attack_check(rrdpath, ifce)
    if ds0An or ds1An:
        draw_graph(ifce, timestamp)
        cached_anomaly = memc.get(str('%s:%s_error')%(MEMCACHE_PREFIX, graph_slug))
        if cached_anomaly is None:
            memc.set(str('%s:%s_error')%(MEMCACHE_PREFIX,graph_slug), '1', MEMCACHE_TIMEOUT)
            notify(imgpath, ifce)
    return

def graphall():
    for ifce in MONITORED_IFCES:
        timestamp = datetime.datetime.now()
        check_and_mail(ifce, timestamp)
    return

if __name__ == "__main__":
    graphall()


