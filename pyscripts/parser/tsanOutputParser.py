#!/usr/bin/python2.7
import argparse
import logging
import os
import re
import signal
import sys
import time

'''
This python script transfers tsan race report to the format required by
our LLVM pass.
A typical tsan race report line
#0 start_threads /home/ruigu/Workspace/concurrency-exploits/apache-21287/httpd-2.0.48/server/mpm/worker/worker.c:1083:13 (httpd+0x000000575add)
#0 check_grant(THD*, unsigned long, st_table_list*, unsigned int, unsigned int, bool) /home/bg2539/workspace/ConAnalysis/concurrency-exploits/mysql-24988/mysql-5.0.27/sql/sql_acl.cc:3634 (mysqld+0x0000005833fb)
will be changed to
start_threads (worker.c:1083)

'''

# All the defined regular expressions
regCallStackLine = re.compile("[\s]*#[0-9]* ([a-zA-Z0-9_:~]*)([a-zA-Z0-9\*, _&\(\)]*)? "
        "([a-zA-Z0-9_~\./\-]*)(:[0-9]*)(:[0-9]*)? .*")
# Detects the start of a variable write
regWriteStart = re.compile("[\s]*(Write|Previous write).*")
# Detects the start of a variable read
regReadStart = re.compile("[\s]*(Read|Previous read).*")
# Detects the start of a race report block
regBlockStart = re.compile("WARNING: ThreadSanitizer: data race.*$")
# Detects a block break
regBlockBreak = re.compile("==================[\s]*$")
# Detects a line break
regLineBreak = re.compile("[\s]*$")
# Detects the end of a block
regBlockEnd = re.compile("SUMMARY: ThreadSanitizer: data race.*$")

def signal_handler(signal, frame):
    print('Gracefully exit!')
    sys.exit(0)

def writeResult2File(fout, resultList):
    for entry in resultList:
        fout.write("%s" % entry)

def checkBlockIntegrity(baseIndex, fp):
    boudaryIndex = baseIndex
    for i, line in enumerate(fp, 1):
        if i >= baseIndex:
            # Update the new boundary each time we found an end of a block
            blockEnd = regBlockBreak.match(line)
            if blockEnd:
                boudaryIndex = i
    return boudaryIndex

def runOverNight(args):
    baseIndex = 0
    curIndex = 0
    outFileNo = 0
    flagBlockStart = False
    flagReadStart = False

    try:
        fp = open(args.raceReportIn, "r")
    except IOError:
        sys.stderr.write('Error: Input file does not exist!\n')
        exit(1)

    resultList = []
    while True:
        boudaryIndex = checkBlockIntegrity(baseIndex, fp)
        logging.debug("End boudary is " + str(boudaryIndex))
        fp.seek(0)
        for i, line in enumerate(fp, 1):
            if i < baseIndex:
                continue
            elif i >= boudaryIndex:
                time.sleep(5)
                break
            blockStart = regBlockStart.match(line)
            blockEnd = regBlockEnd.match(line)
            readStart = regReadStart.match(line)
            callStackLine = regCallStackLine.match(line)
            lineBreak = regLineBreak.match(line)
            if blockStart:
                logging.debug('Line ' + str(i) + ": Block Start")
                flagBlockStart = True
            elif readStart:
                logging.debug('Line ' + str(i) + ": Read Start")
                flagReadStart = True
                flagBlockStart = True
            elif callStackLine:
                if flagReadStart and flagBlockStart:
                    fileName = os.path.basename(os.path.normpath(callStackLine.group(3)))
                    logging.debug('Line ' + str(i) + ": Writing Content")
                    resultList.append(callStackLine.group(1) + " "
                            + "(" + fileName + callStackLine.group(4) + ")\n")
            elif lineBreak:
                logging.debug('Line ' + str(i) + ": Line Break")
                if len(resultList) > 0:
                    fout = open(args.raceReportOut + str(outFileNo) + ".race", "w")
                    outFileNo += 1
                    writeResult2File(fout, resultList)
                    fout.close()
                    del resultList[:]
                flagReadStart = False
            elif blockEnd:
                logging.debug('Line ' + str(i) + ": Block Ends")
                flagBlockStart = False
                flagReadStart = False
                if len(resultList) > 0:
                    fout = open(args.raceReportOut + str(outFileNo) + ".race", "w")
                    outFileNo += 1
                    writeResult2File(fout, resultList)
                    fout.close()
                    del resultList[:]
        if not flagBlockStart and not flagReadStart:
            baseIndex = boudaryIndex
    fp.close()

def runNormalSyncLoop(args):
    baseIndex = 0
    curIndex = 0
    outFileNo = 0
    flagBlockStart = False
    flagReadStart = False
    flagWriteStart = False

    try:
        fp = open(args.raceReportIn, "r")
    except IOError:
        sys.stderr.write('Error: Input file does not exist!\n')
        exit(1)

    writeResultList = []
    readResultList = []

    boudaryIndex = checkBlockIntegrity(baseIndex, fp)
    logging.debug("End boudary is " + str(boudaryIndex))
    fp.seek(0)
    for i, line in enumerate(fp, 1):
        if i < baseIndex:
            continue
        elif i >= boudaryIndex:
            break
        blockStart = regBlockStart.match(line)
        blockBreak = regBlockBreak.match(line)
        blockEnd = regBlockEnd.match(line)
        writeStart = regWriteStart.match(line)
        readStart = regReadStart.match(line)
        callStackLine = regCallStackLine.match(line)
        lineBreak = regLineBreak.match(line)
        if blockStart:
            logging.debug('Line ' + str(i) + ": Block Start")
            flagBlockStart = True
        elif writeStart:
            logging.debug('Line ' + str(i) + ": Write Start")
            flagWriteStart = True
            flagReadStart = False
            flagBlockStart = True
        elif readStart:
            logging.debug('Line ' + str(i) + ": Read Start")
            flagReadStart = True
            flagBlockStart = True
        elif callStackLine:
            if flagReadStart and flagBlockStart:
                fileName = os.path.basename(os.path.normpath(callStackLine.group(3)))
                if fileName == "tsan_interceptors.cc" or fileName == "sanitizer_common_interceptors.inc" or fileName == "tsan_new_delete.cc":
                    if args.outputtype != "verifier":
                        flagReadStart = False
                        flagBlockStart = False
                    continue
                logging.debug('Line ' + str(i) + ": Writing Content")
                if len(readResultList) == 0: 
                    readResultList.append(callStackLine.group(1) + " "
                            + "(" + fileName + callStackLine.group(4) + ")\n")
            if flagWriteStart and flagBlockStart:
                fileName = os.path.basename(os.path.normpath(callStackLine.group(3)))
                if fileName == "tsan_interceptors.cc" or fileName == "sanitizer_common_interceptors.inc" or fileName == "tsan_new_delete.cc":
                    if args.outputtype != "verifier":
                        flagWriteStart = False
                        flagBlockStart = False
                    continue
                logging.debug('Line ' + str(i) + ": Writing Content")
                if len(writeResultList) == 0:
                    writeResultList.append(callStackLine.group(1) + " "
                            + "(" + fileName + callStackLine.group(4) + ")\n")
        elif lineBreak:
            logging.debug('Line ' + str(i) + ": Line Break")
            if len(writeResultList) > 0 and len(readResultList) > 0:
                fout = open(args.raceReportOut + str(outFileNo) + ".race", "w")
                outFileNo += 1
                writeResult2File(fout, writeResultList)
                writeResult2File(fout, readResultList)
                fout.close()
                del writeResultList[:]
                del readResultList[:]
            flagReadStart = False
            flagWriteStart = False
        elif blockBreak:
            flagReadStart = False
            flagWriteStart = False
            flagBlockStart = False
            del writeResultList[:]
            del readResultList[:]
        elif blockEnd:
            logging.debug('Line ' + str(i) + ": Block Ends")
            flagBlockStart = False
            flagReadStart = False
            flagWriteStart = False
            if len(writeResultList) > 0 and len(readResultList) > 0:
                fout = open(args.raceReportOut + str(outFileNo) + ".race", "w")
                outFileNo += 1
                writeResult2File(fout, writeResultList)
                writeResult2File(fout, readResultList)
                fout.close()
                del writeResultList[:]
                del readResultList[:]
    fp.close()

def runNormalConAnalysis(args):
    baseIndex = 0
    curIndex = 0
    outFileNo = 0
    flagBlockStart = False
    flagReadStart = False

    try:
        fp = open(args.raceReportIn, "r")
    except IOError:
        sys.stderr.write('Error: Input file does not exist!\n')
        exit(1)

    resultList = []

    boudaryIndex = checkBlockIntegrity(baseIndex, fp)
    logging.debug("End boudary is " + str(boudaryIndex))
    fp.seek(0)
    for i, line in enumerate(fp, 1):
        if i < baseIndex:
            continue
        elif i >= boudaryIndex:
            break
        blockStart = regBlockStart.match(line)
        blockEnd = regBlockEnd.match(line)
        readStart = regReadStart.match(line)
        callStackLine = regCallStackLine.match(line)
        lineBreak = regLineBreak.match(line)
        if blockStart:
            logging.debug('Line ' + str(i) + ": Block Start")
            flagBlockStart = True
        elif readStart:
            logging.debug('Line ' + str(i) + ": Read Start")
            flagReadStart = True
            flagBlockStart = True
        elif callStackLine:
            if flagReadStart and flagBlockStart:
                fileName = os.path.basename(os.path.normpath(callStackLine.group(3)))
                if fileName == "tsan_interceptors.cc" or fileName == "sanitizer_common_interceptors.inc" or fileName == "tsan_new_delete.cc":
                    continue
                logging.debug('Line ' + str(i) + ": Writing Content")
                resultList.append(callStackLine.group(1) + " "
                        + "(" + fileName + callStackLine.group(4) + ")\n")
        elif lineBreak:
            logging.debug('Line ' + str(i) + ": Line Break")
            if len(resultList) > 0:
                fout = open(args.raceReportOut + str(outFileNo) + ".race", "w")
                outFileNo += 1
                writeResult2File(fout, resultList)
                fout.close()
                del resultList[:]
            flagReadStart = False
        elif blockEnd:
            logging.debug('Line ' + str(i) + ": Block Ends")
            flagBlockStart = False
            flagReadStart = False
            if len(resultList) > 0:
                fout = open(args.raceReportOut + str(outFileNo) + ".race", "w")
                outFileNo += 1
                writeResult2File(fout, resultList)
                fout.close()
                del resultList[:]
    if not flagBlockStart and not flagReadStart:
            baseIndex = boudaryIndex
    fp.close()

def main(args):
    if args.mode == "overnight":
        runOverNight(args)
    elif args.mode == "normal":
        if args.outputtype == "conanalysis":
            runNormalConAnalysis(args)
        else:
            runNormalSyncLoop(args)
    else:
        sys.stderr.write('Error: Unrecognizable mode\n')
        exit(1)

if __name__=='__main__':
    ''' There are two modes for this script. One is overnight mode and the other
        one is normal mode. Overnight mode will check the race report generated
        by the race detector every 10s and parse the output and feed them into
        out backend. Normal mode will only parse the output once.
    '''
    parser = argparse.ArgumentParser(description='tsan output parser')
    parser.add_argument('--mode', type=str, dest="mode",
            action="store", default="normal", required=True,
            help="Running mode [ overnight | normal ]")
    # Generating both type of output doesn't make any sense.
    # We want to first generate syncloop and then generate conanalysis
    # based on the result of syncloop
    parser.add_argument('--outputtype', type=str, dest="outputtype",
            action="store", default="syncloop", required=True,
            help="Running type [ conanalysis | syncloop | verifier]")
    parser.add_argument('--input', type=str, dest="raceReportIn",
            action="store", default="none", required=True,
            help="tsan raw race report")
    parser.add_argument('--output', type=str, dest="raceReportOut",
            action="store", default="none", required=True,
            help="Parsed race report")
    args = parser.parse_args()
    # Set up the signal handler
    signal.signal(signal.SIGINT, signal_handler)
    # Set up the logging system
    logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(levelname)s %(message)s',
            filename='parser.log',
            filemode='w')
    logging.debug("Script starts")
    main(args)
