#!/usr/bin/python2.7
import argparse
import logging
import re
import signal
import sys
import time

'''
This python script transfers valgrind race report to the format required by
our LLVM pass.
A typical valgrind race report line
==7832==    at 0x8068BB7: ap_buffered_log_writer (mod_log_config.c:1345)
will be changed to
ap_buffered_log_writer (mod_log_config.c:1345)

==24571== Possible data race during read of size 4 at 0x2E277D8 by thread #4
==24571== This conflicts with a previous write of size 4 by thread #3
'''

# All the defined regular expressions
regCallStackLine = re.compile("==[0-9]*==[\s]*(at|by) "
        "[0-9A-Fx]*: ([a-zA-Z0-9_:~<> \(\)\*,&]*)(\([0-9A-Za-z\*_, \(\)&]*\))? "
        "(\([a-zA-Z0-9_\.]*:[0-9]*\))")
# Detects the output of a racing variable
regRacingVar = re.compile('==[0-9]*==  (Location|Address) [a-z0-9 ]*'
        '"([0-9A-Za-z_\.\->]*)"')
# Detects the start of a variable write
regWriteStart = re.compile("==[0-9]*== (Possible data race during write|"
        "This conflicts with a previous write).*$")
# Detects the start of a variable read
regReadStart = re.compile("==[0-9]*== (Possible data race during read|"
        "This conflicts with a previous read).*$")
# Detects the start of a race report block
regBlockStart = re.compile("==[0-9]*== [\-]+$")
# Detects a line break
regLineBreak = re.compile("==[0-9]*==[\s]*$")
# Detects the end of a block
regBlockEnd = re.compile("==[0-9]*==  Block was alloc.*$")
# Detects the end of read
regReadEnd = re.compile("==[0-9]*==  Address.*$")

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
            blockEnd = regLineBreak.match(line)
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
            readEnd = regReadEnd.match(line)
            callStackLine = regCallStackLine.match(line)
            lineBreak = regLineBreak.match(line)
            #racingVar = regRacingVar.match(line)
            if blockStart:
                logging.debug('Line ' + str(i) + ": Block Start")
                flagBlockStart = True
            elif readStart:
                logging.debug('Line ' + str(i) + ": Read Start")
                flagReadStart = True
                flagBlockStart = True
            elif readEnd:
                logging.debug('Line ' + str(i) + ": Read End")
                flagReadStart = False
            elif callStackLine:
                if flagReadStart and flagBlockStart:
                    if callStackLine.group(2) != "mythread_wrapper":
                        logging.debug('Line ' + str(i) + ": Writing Content")
                        resultList.append(callStackLine.group(2) + " "
                                + callStackLine.group(4) + "\n")
                    else:
                        flagReadStart = False
            # We don't handle racing variable for now.
            #elif racingVar:
                #logging.debug('Line ' + str(i) + ": Racing Variable")
                #if len(resultList) > 0:
                    #fout = open(args.raceReportOut + str(outFileNo), "w")
                    #flagReadStart = False
                    #writeResult2File(fout, resultList)
                    #fout.close()
                    #del resultList[:]
                #flagBlockStart = False
                #flagReadStart = False
            elif lineBreak:
                logging.debug('Line ' + str(i) + ": Line Break")
                if len(resultList) > 0:
                    fout = open(args.raceReportOut + str(outFileNo), "w")
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
                    fout = open(args.raceReportOut + str(outFileNo), "w")
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
        blockEnd = regBlockEnd.match(line)
        readStart = regReadStart.match(line)
        writeStart = regWriteStart.match(line)
        readEnd = regReadEnd.match(line)
        callStackLine = regCallStackLine.match(line)
        lineBreak = regLineBreak.match(line)
        #racingVar = regRacingVar.match(line)
        if blockStart:
            logging.debug('Line ' + str(i) + ": Block Start")
            flagBlockStart = True
            del writeResultList[:]
            del readResultList[:]
            flagReadStart = False
            flagWriteStart = False
        elif readStart:
            logging.debug('Line ' + str(i) + ": Read Start")
            flagReadStart = True
            flagBlockStart = True
        elif writeStart:
            logging.debug('Line ' + str(i) + ": Write Start")
            flagWriteStart = True
            flagBlockStart = True
        elif readEnd:
            logging.debug('Line ' + str(i) + ": Read End")
            flagReadStart = False
        elif callStackLine:
            logging.debug('Line ' + str(i) + ": Call Stack Line")
            if flagReadStart and flagBlockStart:
                if callStackLine.group(2) != "mythread_wrapper":
                    if len(readResultList) == 0: 
                        logging.debug('Line ' + str(i) + ": Writing Content")
                        readResultList.append(callStackLine.group(2) + " "
                                + callStackLine.group(4) + "\n")
                else:
                    flagReadStart = False
            if flagWriteStart and flagBlockStart:
                if callStackLine.group(2) != "mythread_wrapper":
                    if len(writeResultList) == 0: 
                        logging.debug('Line ' + str(i) + ": Writing Content")
                        writeResultList.append(callStackLine.group(2) + " "
                                + callStackLine.group(4) + "\n")
                else:
                    flagWriteStart = False
        # We don't handle racing variable for now.
        #elif racingVar:
            #logging.debug('Line ' + str(i) + ": Racing Variable")
            #if len(resultList) > 0:
                #fout = open(args.raceReportOut + str(outFileNo), "w")
                #flagReadStart = False
                #writeResult2File(fout, resultList)
                #fout.close()
                #del resultList[:]
            #flagBlockStart = False
            #flagReadStart = False
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
        #elif blockEnd:
        #    logging.debug('Line ' + str(i) + ": Block Ends")
        #    flagBlockStart = False
        #    flagReadStart = False
        #    if len(writeResultList) > 0 and len(readResultList) > 0:
        #        fout = open(args.raceReportOut + str(outFileNo), "w")
        #        outFileNo += 1
        #        writeResult2File(fout, writeResultList)
        #        writeResult2File(fout, readResultList)
        #        fout.close()
        #        del writeResultList[:]
        #        del readResultList[:]
    fp.close()

def main(args):
    if args.mode == "overnight":
        runOverNight(args)
    elif args.mode == "normal":
        if args.outputtype == "conanalysis":
            runNormalConAnalysis(args)
        else:
            logging.debug("Enter syncloop parsing:")
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
    parser = argparse.ArgumentParser(description='Valgrind output parser')
    parser.add_argument('--mode', type=str, dest="mode",
            action="store", default="normal", required=True,
            help="Running mode [ overnight | normal ]")
    # We want to first generate syncloop and then generate conanalysis
    # based on the result of syncloop
    parser.add_argument('--outputtype', type=str, dest="outputtype",
            action="store", default="syncloop", required=True,
            help="Running type [ conanalysis | syncloop | verifier]")
    parser.add_argument('--input', type=str, dest="raceReportIn",
            action="store", default="none", required=True,
            help="Valgrind raw race report")
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
