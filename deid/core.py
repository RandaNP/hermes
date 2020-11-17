"""
deid/core.py 
"""

import logging
import pprint
from datetime import datetime
import daiquiri
import requests
import inspect


# levelname = INFO / DEBUG ....
# name = nome del logger

daiquiri.setup(
    level=logging.INFO,
    outputs=(
        daiquiri.output.Stream(
            formatter=daiquiri.formatter.ColorFormatter(
                fmt="%(levelname)s (%(name)s): %(message)s" 
            )
        ),
    ),
)

deidLogger = daiquiri.getLogger("core_deidapi")


#-------------------------------------------
# Description: Exception list           
# ------------------------------------------
# @param 
# @return -
# ------------------------------------------

class deidError(Exception):
    pass

class deidExamMultiplyFound(Exception):
    pass

class deidExamNotFound(Exception):
    pass
#-------------------------------------------
# Description: Ritorna un esame (se esiste) [GET]           
# ------------------------------------------
# @param 
# @return -
# ------------------------------------------
def deidExamExist(path, studyInstanceUID):

    funcName = inspect.currentframe().f_code.co_name
    deidLogger.debug( "{} (funcName)" .format(funcName) )

    deidLogger.debug("path = {}".format(path))
    deidLogger.debug("StudyInstanceUID = {}".format(studyInstanceUID) )

    try:

        resp = requests.get (
            url = path + "/v1/exams?studyInstanceUID=" + studyInstanceUID ,
            headers = {'Content-type': 'application/json'}
        ).json()

        deidLogger.debug( "deidExamExist = {}".format ( resp ) )
        
        # Nota. Se la chiamata verso l'API non va a buon fine viene 
        #       generata una eccezione di tipo ConnectionError

        # TESTING PURPOSE ONLY
        #resp['data'] = []

    except requests.exceptions.ConnectionError:    

        # Raise exception to calling 
        raise deidError( "ConnectionError to deidAPI ({})".format(funcName) )
    '''
    if ( len(resp['data']) != 1 ): 
        raise deidError("deidAPI founded {} Exam! ({})".format(len(resp['data']), funcName ) )
    '''

    if ( len(resp['data']) == 0 ): 
        raise deidExamNotFound("deidAPI founded 0 Exam! ({})".format(funcName) )
    
    elif ( len(resp['data']) > 1 ):
        raise deidExamMultiplyFound("deidAPI founded Multiply{} Exam! ({})".format(len(resp['data']), funcName ) )
        #APP_LOGGER.info("StudyInstanceUID = " + ds.StudyInstanceUID + " -> NOT FOUND in DEID-DB")

    deidLogger.info("StudyInstanceUID = {} (id = {}) -> FOUNDED ({})".format(studyInstanceUID, resp['data'][0]['id'], resp['data'][0]['status']) )
    return resp['data'][0]

#-------------------------------------------
# Description: Aggiorna un esame [PATCH]          
# ------------------------------------------
# @param 
# @return -
# ------------------------------------------
def deidExamUpdate( path, studyInstanceUID, resId, newState):

    funcName = inspect.currentframe().f_code.co_name
    deidLogger.debug( "{} (funcName)" .format(funcName) )

    deidLogger.debug( "path = {}".format(path) )
    deidLogger.debug( "resId = {}".format(resId) )
    deidLogger.debug( "newState = {}".format(newState) )

    fullPath = path + '/v1/exams/' + str(resId)
    deidLogger.debug( "fullPath = {}".format(fullPath) )

    try:

        resp = requests.patch (  
            url = fullPath,
            json = {'status': newState},
            headers = {'Content-type': 'application/json'}
        ).json()

        # This API return TRUE or (FALSE, msg)
        deidLogger.debug( "{}: {}".format ( funcName, resp ) )
    
    except requests.exceptions.ConnectionError:    

        # Raise exception to calling 
        raise deidError( "ConnectionError to deidAPI {}".format(funcName) )

    # Check other exception
    if resp['success'] == False:
        raise deidError('deidAPI returned False (msg = {}) ({})'.format( resp['message'], funcName ) )

    deidLogger.info('StudyInstanceUID = {} (id = {}) -> set to {}!'.format( studyInstanceUID, resId, newState ) )
    return resp['success']