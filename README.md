rady
====

A quite simple yet effective rrd-based tool to detect network anomalies on core uplink interfaces. 
Rady (Rapid Anomany Detection in pYthon) is yet another tool that performs plain statistical analysis on rrd files.
Currently it is tested on a 20Gbps backbone link with 6Gbps avg. traffic and it seems to be sensing a vast majority of network anomalies.
Detection relies solely on rrd files analysis and a Standard Deviation - based algorithm powers the whole proccess. As a next step the 
EWMA algorithm will be supported as well.

Documentation is not complete yet, however you can try the tool...

##Dependencies##

* python-rrdtool
* python-pynetsnmp
* python-numpy
* memcached
* python-memcache

A mail server able to send out emails.

##Installation##

Make sure you have installed the aforementioned dependencies.
Git clone or download the tool to a desired folder and... that's it.
For the sake of this quick reference guide, let's assume that rady is downloaded at::

    /srv/rady
 
Time to do some configuration.

##Configuration##
Copy the settings.py.dist file to settings.py::

    $cp settings.py.dist settings.py
    
Edit the settings.py file with your favorite editor and adjust the following for a first glorious run::

    THRESHOLD: We have tested successfully with 0.20 (20% above stdev upper limit) but you can try it yourself till you reach a balance state. 

Remember the wise quote by Miyagi (Karate Kid)::

    Better learn balance. Balance is key. Balance good, karate good. Everything good. Balance bad, better pack up, go home. Understand?
   
Enough with wisdom, let's continue with the rest of parameters::

    MAIL_TO: List of contacts that are to be notifies in case of an anomaly being detected
     



