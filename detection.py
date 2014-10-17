import rrdtool
import math
import numpy

def stdev_algo(rrdfilepath, ifce):
    THRESHOLD = ifce['THRESHOLD']
    data = rrdtool.fetch(str(rrdfilepath), 'AVERAGE', '--start', '-360')
    data = data[2]
    last = data[-1]
    if (last[0] is None) & (last[1] is None):
        data.pop(-1)
    last_value = data.pop(-1)
    lastds0 = last_value[0]
    lastds1 = last_value[1]
    ds0 = []
    ds1 = []
    for d in data:
        try:
            ds0.append(d[0]*8)        
            ds1.append(d[1]*8)
        except TypeError:
            return False, False
    ds0Anomaly = stdev_detect(ds0, THRESHOLD)
    ds1Anomaly = stdev_detect(ds1, THRESHOLD)
    return ds0Anomaly, ds1Anomaly

def stdev_detect(ds, threshold):        
    dsMean = numpy.mean(ds)
    dsStd = numpy.std(ds)
    dsUpper = dsMean+dsStd
    dsLower = dsMean-dsStd
    dsMax = numpy.amax(ds)
    dsMin = numpy.amin(ds)
    dsRelDiffHi = math.fabs((dsMax-dsUpper)/dsUpper)
    dsRelDiffLo = math.fabs((dsMin-dsLower)/dsLower)
    dsBigDiff = False
    if dsRelDiffHi > threshold:
        dsBigDiff = True
    if dsRelDiffLo > threshold:
        dsBigDiff = True
    dsAnomaly = False
    if dsBigDiff and dsMax > dsUpper:
        dsAnomaly = True
    if dsBigDiff and dsMin < dsLower:
        dsAnomaly = True
    return dsAnomaly 