"""
senderTEST.py
=============
The senderTEST service is responsible to fetch exams with "NUOVO" state from 
deid-dB and call PACS 228 to send exam to router for deidentification"
"""

import logging
import os
import signal
import sys
import time
#from datetime import timedelta, datetime
from pathlib import Path
#from shutil import rmtree
from pprint import pprint
import daiquiri
#import graphyte
import requests
import subprocess

#import common.config as config
import common.helper as helper
#import common.monitor as monitor
import common.version as version
#from common.monitor import send_series_event

ipApiDeid = "http://192.168.179.229:5001"

daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.Stream(
            formatter=daiquiri.formatter.ColorFormatter(
                fmt="%(color)s%(levelname)-8.8s " "%(name)s: %(message)s%(color_stop)s"
            )
        ),
    ),
)

logger = daiquiri.getLogger("senderTEST")


def receiveSignal(signalNumber, frame):
    logger.info("Received:",signalNumber)
    return

def terminateProcess(signalNumber, frame):

    """Triggers the shutdown of the service."""
    helper.g_log("events.shutdown", 1)
    logger.info("Shutdown requested")
    logger.info("Is running?" + str(main_loop.is_running))
    
    #monitor.send_event(monitor.h_events.SHUTDOWN_REQUEST, monitor.severity.INFO)
    # Note: main_loop can be read here because it has been declared as global variable
    
    if "main_loop" in globals() :#and main_loop.is_running:
        main_loop.stop()
    helper.triggerTerminate()


def senderTest(args):
    
    resp = {}

    """ Main entry function. """
    
    if helper.isTerminated():
        return

    helper.g_log("events.run",1)

    # Call API for retrieve exam with statusId = 1 (NEW)

    url = ipApiDeid + "/v1/exams?statusId=1&limit=1"
    #url = ipApiDeid + "/v1/exams?statusId=1"
 
    try:
        resp = requests.get(
            url,
            headers = {'Content-type': 'application/json'}
        ).json()
     
    except requests.exceptions.ConnectionError:
        
        logger.error("{} Not Respond. Connection Error? ".format(url))
        return

    except ValueError: # Quando si presenta il problema "overflow sqlalchemy"

        logger.error("Value Error (QueuePool limit?) ")
        return
     
    # If no Exception raise, check if API respose is not empty"

    if resp['data']: 

        logger.info("Processing {} exams".format(len (resp['data'])))

        # Per ogni esame ricevuto fare un movescu dal pacs 228
        # verso il router stesso per effettuare la deidentificazione.
        
        for exam in resp['data']:
            
            logger.info("Processing: " + str(exam['studyInstanceUID']))

            # Check if PACS 228 is online
            try:
                out = subprocess.check_output("echoscu -v 192.168.179.228 11112 -aec qpacs", shell=True)
                logger.info("Pacs 228 is online! Go on...")
            
            except subprocess.CalledProcessError as err:
                
                #print("err = " + str(err))
                #print("ret_code = " + str(err.returncode))
                logger.error("Pacs 228 is not reachable! (echoscu fail)")
                return

   else:

        logger.info("No Exam found in deid-Db with statusId = 1")


def exit_senderTest(args):
    """ Stop the asyncio event loop. """
    helper.loop.call_soon_threadsafe(helper.loop.stop)


if __name__ == "__main__":
    
    logger.info("")
    logger.info(f"SenderTEST ver {version.hermes_version}")
    logger.info("-------------------")
    logger.info("")

    # Register system signals to be caught
    signal.signal(signal.SIGINT, terminateProcess)
    signal.signal(signal.SIGQUIT, receiveSignal)
    signal.signal(signal.SIGILL, receiveSignal)
    signal.signal(signal.SIGTRAP, receiveSignal)
    signal.signal(signal.SIGABRT, receiveSignal)
    signal.signal(signal.SIGBUS, receiveSignal)
    signal.signal(signal.SIGFPE, receiveSignal)
    signal.signal(signal.SIGUSR1, receiveSignal)
    signal.signal(signal.SIGSEGV, receiveSignal)
    signal.signal(signal.SIGUSR2, receiveSignal)
    signal.signal(signal.SIGPIPE, receiveSignal)
    signal.signal(signal.SIGALRM, receiveSignal)
    signal.signal(signal.SIGTERM, terminateProcess)


    global main_loop
    main_loop = helper.RepeatedTimer(
       #config.hermes["cleaner_scan_interval"], clean, exit_cleaner, {}
       1, senderTest, exit_senderTest, {}
    )
    main_loop.start()

    helper.g_log("events.boot", 1)

    # Start the asyncio event loop for asynchronous function calls
    helper.loop.run_forever()

    # Process will exit here once the asyncio loop has been stopped
    # monitor.send_event(monitor.h_events.SHUTDOWN, monitor.severity.INFO)
    logger.info("Going down now")





# ==========================

         #subprocess.call(["ls","-l"])
            #subprocess.call(["echoscu","-v","192.168.179.228","11112","-aec","qpacs"])

            #proc = subprocess.Popen(["echoscu","-v","192.168.179.228","11112","-aec","qpacs"], stdout=subprocess.PIPE)
            #stdout = proc.communicate()
            #print ("Out = {}".format(stdout))
    

            '''
            #out1 = subprocess.run(
            command = f'echoscu -v -to 10 -aec qpacs 192.168.179.228 11112 '
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(p)
            print(p.returncode)
            line2=''
            while True:
                line = p.stdout.readline().rstrip()
                line2 = line2+'\n'+str(line)
                #print(line2)
                if not line:
                    break
            print(line2)    
            #if "(Success)" in str(out):
            #    logger.info("Suc")
            '''

            #subprocess.run(["ls","-l", "/dev/null"], capture_output=True)

 
