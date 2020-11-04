#!/usr/bin/env python
"""An implementation of a Storage Service Class Provider (Storage SCP)."""

import argparse
import logging
from logging.config import fileConfig
import os
import socket
import sys
import subprocess
import re
import requests
import json
from datetime import datetime
import string
import ipaddress
from pathlib import Path
#from qTcApi import qtcApiLogin, qtcApiLogout, qtcApiExaminationCreate, qtcApiExaminationList, qtcApiExamSearch
from qtc.api2 import *
from qtc.core import *

from pydicom.dataset import Dataset
from pydicom.uid import (
    ExplicitVRLittleEndian,
    ImplicitVRLittleEndian,
    ExplicitVRBigEndian,
    DeflatedExplicitVRLittleEndian,
    JPEGLossless # per UNIME
)

from pynetdicom import (
    AE, evt,
    StoragePresentationContexts,
    VerificationPresentationContexts,
    PYNETDICOM_IMPLEMENTATION_UID,
    PYNETDICOM_IMPLEMENTATION_VERSION
)

#add SOP Classes as DICOM Conformance Statement dcm4che Archive 5
from moreSOPClass import _more_sop_class
from pynetdicom import build_context

MoreStoragePresentationContexts = [
   build_context(uid) for uid in sorted(_more_sop_class.values())
]

StoragePresentationContexts = StoragePresentationContexts + MoreStoragePresentationContexts

# App-specific includes
import common.config as config

# For surpress Insecure Warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Deid temp workaround includes
import tagfunctions
from tagactions import tags
# DeIdentificationMethodCodeSeq based on Table CID 7050 from DICOM Standard
deidMeth = {
    '113100': 'Basic Application Confidentiality Profile',
    '113101': 'Clean Pixel Data Option',
    '113102': 'Clean Recognizable Visual Features Option',
    '113103': 'Clean Graphics Option',
    '113104': 'Clean Structured Content Option',
    '113105': 'Clean Descriptors Option',
    '113106': 'Retain Longitudinal With Full Dates Option',
    '113107': 'Retain Longitudinal With Modified Dates Option',
    '113108': 'Retain Patient Characteristics Option',
    '113109': 'Retain Device Identity Option',
    '113110': 'Retain UIDs',
    '113111': 'Retain Safe Private Option',
}
###

VERSION = '0.5.1'

def _setup_argparser():
    """Setup the command line arguments"""
    # Description
    parser = argparse.ArgumentParser(
        description="The storescp application implements a Service Class "
                    "Provider (SCP) for the Storage SOP Class. It listens "
                    "for a DICOM C-STORE message from a Service Class User "
                    "(SCU) and stores the resulting DICOM dataset.",
        usage="storescp [options] port")

    # Parameters
    req_opts = parser.add_argument_group('Parameters')
    req_opts.add_argument("port",
                          help="TCP/IP port number to listen on",
                          type=int)
    req_opts.add_argument("--bind_addr",
                          help="The IP address of the network interface to "
                          "listen on. If unset, listen on all interfaces.",
                          default='')

    # General Options
    gen_opts = parser.add_argument_group('General Options')
    gen_opts.add_argument("--version",
                          help="print version information and exit",
                          action="store_true")
    gen_opts.add_argument("-q", "--quiet",
                          help="quiet mode, print no warnings and errors",
                          action="store_true")
    gen_opts.add_argument("-v", "--verbose",
                          help="verbose mode, print processing details",
                          action="store_true")
    gen_opts.add_argument("-d", "--debug",
                          help="debug mode, print debug information",
                          action="store_true")
    gen_opts.add_argument("-ll", "--log-level", metavar='[l]',
                          help="use level l for the APP_LOGGER (fatal, error, warn, "
                               "info, debug, trace)",
                          type=str,
                          choices=['fatal', 'error', 'warn',
                                   'info', 'debug', 'trace'])
    gen_opts.add_argument("-lc", "--log-config", metavar='[f]',
                          help="use config file f for the APP_LOGGER",
                          type=str)

    # Network Options
    net_opts = parser.add_argument_group('Network Options')
    net_opts.add_argument("-aet", "--aetitle", metavar='[a]etitle',
                          help="set my AE title (default: STORESCP)",
                          type=str,
                          default='STORESCP')
    net_opts.add_argument("-to", "--timeout", metavar='[s]econds',
                          help="timeout for connection requests",
                          type=int,
                          default=None)
    net_opts.add_argument("-ta", "--acse-timeout", metavar='[s]econds',
                          help="timeout for ACSE messages",
                          type=int,
                          default=30)
    net_opts.add_argument("-td", "--dimse-timeout", metavar='[s]econds',
                          help="timeout for DIMSE messages",
                          type=int,
                          default=None)
    net_opts.add_argument("-pdu", "--max-pdu", metavar='[n]umber of bytes',
                          help="set max receive pdu to n bytes (4096..131072)",
                          type=int,
                          default=16384)

    # Transfer Syntaxes
    ts_opts = parser.add_argument_group('Preferred Transfer Syntaxes')
    ts_opts.add_argument("-x=", "--prefer-uncompr",
                         help="prefer explicit VR local byte order (default)",
                         action="store_true")
    ts_opts.add_argument("-xe", "--prefer-little",
                         help="prefer explicit VR little endian TS",
                         action="store_true")
    ts_opts.add_argument("-xb", "--prefer-big",
                         help="prefer explicit VR big endian TS",
                         action="store_true")
    ts_opts.add_argument("-xi", "--implicit",
                         help="accept implicit VR little endian TS only",
                         action="store_true")

    # Output Options
    out_opts = parser.add_argument_group('Output Options')
    out_opts.add_argument('-od', "--output-directory", metavar="[d]irectory",
                          help="write received objects to existing directory d",
                          type=str)

    # Miscellaneous
    misc_opts = parser.add_argument_group('Miscellaneous')
    misc_opts.add_argument('--ignore',
                           help="receive data but don't store it",
                           action="store_true")

    return parser.parse_args()


args = _setup_argparser()

# Logging/Output
def setup_logger():
    """Setup the echoscu logging"""
    logger = logging.Logger('storescp')
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    #logger.setLevel(logging.ERROR)
    logger.setLevel(logging.INFO)

    return logger

APP_LOGGER = setup_logger()

def _setup_logging(level):
    APP_LOGGER.setLevel(level)
    pynetdicom_logger = logging.getLogger('pynetdicom')
    handler = logging.StreamHandler()
    pynetdicom_logger.setLevel(level)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    pynetdicom_logger.addHandler(handler)

if args.quiet:
    for hh in APP_LOGGER.handlers:
        APP_LOGGER.removeHandler(hh)

    APP_LOGGER.addHandler(logging.NullHandler())

if args.verbose:
    _setup_logging(logging.INFO)

if args.debug:
    _setup_logging(logging.DEBUG)

if args.log_level:
    levels = {'critical' : logging.CRITICAL,
              'error'    : logging.ERROR,
              'warn'     : logging.WARNING,
              'info'     : logging.INFO,
              'debug'    : logging.DEBUG}
    _setup_logging(levels[args.log_level])

if args.log_config:
    fileConfig(args.log_config)

APP_LOGGER.debug('$storescp.py v{0!s}'.format(VERSION))
APP_LOGGER.debug('')

# Telegram BOT Alert
def telegram_bot_sendtext(message, APP_LOGGER):
    #from telegram_bot_secrets import token, chatID
    token = '1397633971:AAGLUuCmc0QhvCXGzkDi04i_bGCfvKslW98'
    chatID = '-1001340592635'
    APP_LOGGER.info(token)
    send_text = 'https://api.telegram.org/bot{}/sendMessage?chat_id={}&parse_mode=Markdown&text={}'.format(token, chatID, message)

    response = requests.get(send_text)

    return response.json()


# Validate port
if isinstance(args.port, int):
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        test_socket.bind((os.popen('hostname').read()[:-1], args.port))
        test_socket.close()
    except socket.error:
        APP_LOGGER.error("Cannot listen on port {0:d}, insufficient priveleges".format(args.port))
        sys.exit()

if args.port == 11112:
    StationAETitle_XNAT = "XNAT_TEST"
    api_deid_path = "http://192.168.179.229:5001"
else:
    StationAETitle_XNAT = "XNAT"
    api_deid_path = "http://192.168.179.229:5000"



# Set Transfer Syntax options
transfer_syntax = [ImplicitVRLittleEndian,
                   ExplicitVRLittleEndian,
                   DeflatedExplicitVRLittleEndian,
                   ExplicitVRBigEndian,
                   JPEGLossless]

if args.prefer_uncompr and ImplicitVRLittleEndian in transfer_syntax:
    transfer_syntax.remove(ImplicitVRLittleEndian)
    transfer_syntax.append(ImplicitVRLittleEndian)

if args.implicit:
    transfer_syntax = [ImplicitVRLittleEndian]

if args.prefer_little and ExplicitVRLittleEndian in transfer_syntax:
    transfer_syntax.remove(ExplicitVRLittleEndian)
    transfer_syntax.insert(0, ExplicitVRLittleEndian)

if args.prefer_big and ExplicitVRBigEndian in transfer_syntax:
    transfer_syntax.remove(ExplicitVRBigEndian)
    transfer_syntax.insert(0, ExplicitVRBigEndian)

def handle_store(event):
    """Handle a C-STORE request.
    Parameters
    ----------
    event : pynetdicom.event.event
        The event corresponding to a C-STORE request. Attributes are:
        * *assoc*: the ``association.Association`` instance that received the
          request
        * *context*: the presentation context used for the request's *Data
          Set* as a ``namedtuple``
        * *request*: the C-STORE request as a ``dimse_primitives.C_STORE``
          instance
        Properties are:
        * *dataset*: the C-STORE request's decoded *Data Set* as a pydicom
          ``Dataset``
    Returns
    -------
    status : pynetdicom.sop_class.Status or int
        A valid return status code, see PS3.4 Annex B.2.3 or the
        ``StorageServiceClass`` implementation for the available statuses
    """
    if args.ignore:
        return 0x0000

    mode_prefixes = {
        'CT Image Storage' : 'CT',
        'Enhanced CT Image Storage' : 'CTE',
        'MR Image Storage' : 'MR',
        'Enhanced MR Image Storage' : 'MRE',
        'Positron Emission Tomography Image Storage' : 'PT',
        'Enhanced PET Image Storage' : 'PTE',
        'RT Image Storage' : 'RI',
        'RT Dose Storage' : 'RD',
        'RT Plan Storage' : 'RP',
        'RT Structure Set Storage' : 'RS',
        'Computed Radiography Image Storage' : 'CR',
        'Ultrasound Image Storage' : 'US',
        'Enhanced Ultrasound Image Storage' : 'USE',
        'X-Ray Angiographic Image Storage' : 'XA',
        'Enhanced XA Image Storage' : 'XAE',
        'Nuclear Medicine Image Storage' : 'NM',
        'Secondary Capture Image Storage' : 'SC'
    }

    ds = event.dataset

    # Because pydicom uses deferred reads for its decoding, decoding errors
    #   are hidden until encountered by accessing a faulty element
    try:
        sop_class = ds.SOPClassUID
        sop_instance = ds.SOPInstanceUID
    except Exception as exc:
        # Unable to decode dataset
        return 0xC210

    try:
        # Get the elements we need
        mode_prefix = mode_prefixes[sop_class.name]
    except KeyError:
        mode_prefix = 'UN'

    filename = '{0!s}.{1!s}'.format(mode_prefix, sop_instance)
    APP_LOGGER.info('Storing DICOM file: {0!s}'.format(filename))

    if os.path.exists(filename):
        APP_LOGGER.warning('DICOM file already exists, overwriting')

    # Presentation context
    cx = event.context

    ## DICOM File Format - File Meta Information Header
    # If a DICOM dataset is to be stored in the DICOM File Format then the
    # File Meta Information Header is required. At a minimum it requires:
    #   * (0002,0000) FileMetaInformationGroupLength, UL, 4
    #   * (0002,0001) FileMetaInformationVersion, OB, 2
    #   * (0002,0002) MediaStorageSOPClassUID, UI, N
    #   * (0002,0003) MediaStorageSOPInstanceUID, UI, N
    #   * (0002,0010) TransferSyntaxUID, UI, N
    #   * (0002,0012) ImplementationClassUID, UI, N
    # (from the DICOM Standard, Part 10, Section 7.1)
    # Of these, we should update the following as pydicom will take care of
    #   the remainder
    meta = Dataset()
    meta.MediaStorageSOPClassUID = sop_class
    meta.MediaStorageSOPInstanceUID = sop_instance
    meta.ImplementationClassUID = PYNETDICOM_IMPLEMENTATION_UID
    meta.TransferSyntaxUID = cx.transfer_syntax

    # The following is not mandatory, set for convenience
    meta.ImplementationVersionName = PYNETDICOM_IMPLEMENTATION_VERSION

    ds.file_meta = meta
    ds.is_little_endian = cx.transfer_syntax.is_little_endian
    ds.is_implicit_VR = cx.transfer_syntax.is_implicit_VR

    status_ds = Dataset()
    status_ds.Status = 0x0000

    # Try to save to output-directory
    if args.output_directory is not None:
        filename = os.path.join(args.output_directory, filename)

    # BCU check
    assocId = event.assoc.name.split('@')[1]
    APP_LOGGER.info('Association ID: {0!s}'.format(assocId))
    callingIP = event.assoc.requestor.info['address']
    APP_LOGGER.info('Calling IP: {0!s}'.format(callingIP))
    callingAETitle = str(event.assoc.requestor.info['ae_title'], encoding='ascii').strip()
    APP_LOGGER.info('Calling AE Title: {0!s}'.format(callingAETitle))

    # Check if study comes from LAN
    LAN = (ipaddress.ip_address(callingIP) in ipaddress.ip_network('192.168.179.0/24')) or (ipaddress.ip_address(callingIP) in ipaddress.ip_network('192.168.1.0/24'))


    APP_LOGGER.info('LAN? {}'.format(LAN))

    try:
        config.read_config()
    except Exception:
        APP_LOGGER.error("Unable to read configuration. Skipping processing.")
        # TO-DO: da integrare con il monitor di hermes
        return 0xA700

    studyProcessed = Path('/'.join([
        config.hermes['success_folder'],
        'BCU_check',
        '_'.join([str(assocId), str(ds.StudyInstanceUID)])
    ]))

    APP_LOGGER.info('Filter XNAT recognizable DICOM modalities')
    modality = str(ds.get('Modality', ''))
    if modality not in ['CR', 'CT', 'MR', 'PT', 'US']:
        APP_LOGGER.warning('Rejected modality {} in {}'.format(modality, str(ds.SeriesInstanceUID)))
        return 0x0000
    APP_LOGGER.info('Insert tag StationAETitle = {}'.format(StationAETitle_XNAT))
    ds.add_new(0x00080055, 'AE', StationAETitle_XNAT)

    patientName = str(ds.get('PatientName', ''))
    if patientName.startswith('MOLIM_ONCO_'):
        patientName = patientName[11:]
    callingAETitle = patientName.split('_', 1)[0]
    APP_LOGGER.info('callingAETitle corrected: {}'.format(callingAETitle))
    accessionNumber = str(ds.get('AccessionNumber', ''))
    studyDate = str(ds.StudyDate)
    studyDateHex = ''.join([
        str(hex(int(studyDate[0:4]) - 1950))[2:],
        str(hex(int(studyDate[4:6])))[2:],
        str(hex(int(studyDate[6:8])))[2:]
    ])


    if not studyProcessed.exists():
        
        url = api_deid_path + "/v1/exams?studyInstanceUID=" + ds.StudyInstanceUID 
    
        APP_LOGGER.debug("Call Api: Exist Exam ({})".format(url)) # Per Debug
        
        resp = requests.get(
            url,
            headers = {'Content-type': 'application/json'}
        ).json()
    
        APP_LOGGER.debug("Resp Api: Exist Exam ({})".format(resp))  # Per Debug

        if resp['success'] is True:
    
            respLenData = len (resp['data'])



            if resp['data'] == []: # Nessun StudyInstaceUID Trovato!
    
                APP_LOGGER.info("StudyInstanceUID = " + ds.StudyInstanceUID + " -> NOT FOUND in DEID-DB")
       
                chars = re.escape(string.punctuation)
                # Institution Name
                institutionName = ds.get("InstitutionName", '').upper()
                institutionName = re.sub(r'['+chars+']', '',institutionName)
    
                APP_LOGGER.debug("institutionName = " + str(institutionName))
    
                # Nota. I campi studyDate e studyDescription non vanno passati nella
                #       creazione dell'esame poichè sarà l'API a crearli secondo 
                #       le regole di deid (come sullo script di deid)
                deidExam = { 
                    'callingAETitle'        : callingAETitle,
    
                    'patientName'           : str(ds.get("PatientName", '')),
                    'patientBirthDate'      : str(ds.get("PatientBirthDate", '')),
                    'fiscalCode'            : '',
            
                    'origPatientID'         : str(ds.get("PatientID", '')),                   
                    'institutionName'       : institutionName, 
                
                    'origStudyDate'         : str(ds.get("StudyDate", '')), 
                    'origStudyDescription'  : str(ds.get("StudyDescription", '')),
                    
                    'studyInstanceUID'      : str(ds.StudyInstanceUID),
                    'assocId'               : assocId,
                    'status'                : 'DEIDENTIFICATO',
                }
                if LAN:
                    deidExam['callingAETitle'] = 'BCU'
    
                APP_LOGGER.debug("Call Api: Create Exam")
                
                resp = requests.post(
                    api_deid_path + '/v1/exams',
                    json = deidExam,
                    headers = {'Content-type': 'application/json'}
                ).json()
               
                # Nota! La chiamata API appena eseguita aggiunge ulteriori 
                #       chiavi al dict ovvero: ['patient']['institution']

                APP_LOGGER.debug("Resp Api: Create Exam {}".format(str(resp)))

                if resp['success']:
                    deidExam = resp['data']
                    #APP_LOGGER.info('deidExam create correctly! {} - {} - {}'.format(callingIP, callingAETitle, ds.StudyInstanceUID))
                    APP_LOGGER.info("StudyInstanceUID = " + ds.StudyInstanceUID + " -> CREATED in DEID-DB")
                else:
                    #APP_LOGGER.error('Unable to create deidExam: {} - {} - {}'.format(callingIP, callingAETitle, ds.StudyInstanceUID))
                    APP_LOGGER.error("StudyInstanceUID = " + ds.StudyInstanceUID + " -> UNABLE to CREATE in DEID-DB")
                    return 0xA700
    
            elif respLenData == 1: # Unico StudyInstaceUID Trovato!
                
                APP_LOGGER.debug("len ( resp['data'] ) = " + str(respLenData) )

                APP_LOGGER.info("StudyInstanceUID = " + ds.StudyInstanceUID + " -> FOUNDED.")
    
                deidExam = resp['data'][0]

                APP_LOGGER.debug("deidExam = " + str(deidExam))
                
            else: # Multipli StudyInstaceUID Trovati!
                
                APP_LOGGER.error("StudyInstanceUID =" + ds.StudyInstanceUID + " -> MULTIPLE STUDY INSTANCE FOUND!.")
                # TO-DO: aggiungere notifica mail
    
        else:
            APP_LOGGER.error("DEID-API NOT AVAILABLE")
            return 0xA700

        deidExam = {
            'dateInterval': deidExam['patient']['dateInterval'],
            'bcuInstitutionId': deidExam['institution']['bcuInstitutionId'],
            'bcuPatientID': deidExam['patient']['bcuPatientID']
        }
        bcuCheckDir = Path('/'.join([
            config.hermes['success_folder'],
            'BCU_check'
        ]))
        bcuCheckDir.mkdir(exist_ok = True)
        studyProcessed.write_text(json.dumps(deidExam))
        
    else: # studyProcessed.exist() == True
        deidExam = json.loads(studyProcessed.read_text())

    if LAN:
        APP_LOGGER.info('INTERNAL DEID XNAT:')  
    else:
        APP_LOGGER.info('DEID XNAT:')  
        ds.remove_private_tags()
        APP_LOGGER.debug('tag privati rimossi')

    APP_LOGGER.debug('deidExam: {}'.format(deidExam))
    
    '''
    resp = requests.post(
        api_deid_path +'/v1/deid',
        json = {
            'dataset': ds,
            'dateInterval': deidExam['dateInterval'],
            'bcuInstitutionId': deidExam['bcuInstitutionId'],
            'bcuPatientID': deidExam['bcuPatientID']
        },
        headers = {'Content-type': 'application/json'}
    ).json()

    if resp['success']:
        APP_LOGGER.info('StudyInstanceUID = {}-> DEID SUCCESS!'.format( ds.StudyInstanceUID ) )
        ds.from_json(resp['data'])           
    
    else:
        status_ds.Status = 0x0110
        status_ds.ErrorComment = 'Internal de-identification error'
        APP_LOGGER.info('StudyInstanceUID = {} -> DEID FAIL!'.format( ds.StudyInstanceUID ) )
        return status_ds
    '''

    # Deid temp workaround
    # prepare deidentification information
    deidMethSeq = []
    for option in ['113100', '113107', '113108', '113109', '113110']: # questa lista potrebbe essere definita nel template e rappresenta le opzioni di deidentificazione usate dal template
        
        deidMethEl = Dataset()
        deidMethEl.CodeValue = option
        deidMethEl.CodingSchemeDesignator = 'DCM'
        deidMethEl.CodingMeaning = deidMeth[option]
        deidMethSeq.append(deidMethEl)

    # BCU Private Block
    # add BlockOwner tag
    ds.add_new(0x00130010, 'CS', 'BCU')
    ds.add_new(0x001310ff, 'IS', deidExam['dateInterval'])
    ds.add_new(0x001310fe, 'CS', deidExam['bcuInstitutionId'])
    ds.add_new(0x001310fd, 'CS', deidExam['bcuPatientID'])

    if not LAN:
        tags["PatientName"]     = ["function", "keeptag"]
        tags["PatientID"]       = ["function", "keeptag"]
        tags["InstitutionName"] = ["function", "keeptag"]

    for tag in tags.keys():
        try:
            operation = tags[tag][0]
            if operation == 'regex':
                pass
            elif operation == 'function':
                exec('tagfunctions.'+tags[tag][1]+'(tag, ds)')
        except:
            pass

    # insert de-identification information
    ds.PatientIdentifiedRemoved = 'YES'
    ds.DeidentificationMethod = '{Per DICOM PS 3.15 AnnexE. Details in 0012,0064}'
    ds.DeidentificationMethodCodeSequence = deidMethSeq
    ds.LongitudinalTemporalInformationModified = 'MODIFIED'

    # REMOVE BCU INTERNAL VARS FROM dataset
    del ds[0x00130010] # Block Owner
    del ds[0x001310ff] # patient.dateInterval
    del ds[0x001310fe] # bcuInstitutionId
    del ds[0x001310fd] # patient.bcuPatientID
    #####

    if LAN:
        studyDate = str(ds.StudyDate)
        studyDateHex = ''.join([
            str(hex(int(studyDate[0:4]) - 1950))[2:],
            str(hex(int(studyDate[4:6])))[2:],
            str(hex(int(studyDate[6:8])))[2:]
        ])

    # add Patient & Study Comment tags
    if LAN:
        project = 'COV19_DB'
        sessionPrefix = 'COV19'
        patientName = str(ds.get('PatientName', ''))
        ds.add_new('PatientComments', 'CS', 'Project:{} Session:{}'.format(project, '_'.join([sessionPrefix, patientName, modality, studyDateHex])))
    else:
        ds.add_new('PatientComments', 'CS', 'Project:{} Session:{}'.format(accessionNumber, '_'.join([accessionNumber, patientName, modality, studyDateHex])))
    ds.add_new('StudyComments', 'CS', '')
   
    try:
        # We use `write_like_original=False` to ensure that a compliant
        #   File Meta Information Header is written
        ds.save_as(filename, write_like_original=False)
  
        # In caso non andasse a buon file la creazione del dcm (ds.save_as) la seguente istruzione (subprocess)
        # non dovrebbe eseguirla e quindi non generare il file .tags
        subgetdcm = subprocess.check_output(['/home/hermes/hermes/bin/getdcmtags', filename, '0.0.0.0:8080'])
  
        status_ds.Status = 0x0000 # Success
    
    except IOError:
        APP_LOGGER.error('Could not write file to specified directory:')
        APP_LOGGER.error("    {0!s}".format(os.path.dirname(filename)))
        APP_LOGGER.error('Directory may not exist or you may not have write '
                     'permission')

        # Failed - Out of Resources - IOError
        status_ds.Status = 0xA700

    except subprocess.CalledProcessError as err:
        APP_LOGGER.error('getdcmtags --> {0!s}'.format(err.output))
        
        # remove filename dcm.
        os.remove(filename)
        
        status_ds.Status = 0xA701

    except:
        APP_LOGGER.error('Could not write file to specified directory:')
        APP_LOGGER.error("    {0!s}".format(os.path.dirname(filename)))
        # Failed - Out of Resources - Miscellaneous error
        status_ds.Status = 0xA701

    '''
    try:
        subgetdcm = subprocess.check_output(['/home/hermes/hermes/bin/getdcmtags', filename, '0.0.0.0:8080'])
    except subprocess.CalledProcessError as err:
        APP_LOGGER.error('getdcmtags --> {0!s}'.format(err.output))
    '''
    APP_LOGGER.info("handle_store END")    
    return status_ds

handlers = [(evt.EVT_C_STORE, handle_store)]

# Test output-directory
if args.output_directory is not None:
    if not os.access(args.output_directory, os.W_OK|os.X_OK):
        APP_LOGGER.error('No write permissions or the output '
                     'directory may not exist:')
        APP_LOGGER.error("    {0!s}".format(args.output_directory))
        sys.exit()

# Create application entity
ae = AE(ae_title=args.aetitle)

# Add presentation contexts with specified transfer syntaxes
for context in StoragePresentationContexts:
    ae.add_supported_context(context.abstract_syntax, transfer_syntax)
for context in VerificationPresentationContexts:
    ae.add_supported_context(context.abstract_syntax, transfer_syntax)

ae.maximum_pdu_size = args.max_pdu

# Set timeouts
ae.network_timeout = args.timeout
ae.acse_timeout = args.acse_timeout
ae.dimse_timeout = args.dimse_timeout

ae.start_server((args.bind_addr, args.port), evt_handlers=handlers)
