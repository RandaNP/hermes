"""
qtc/api2.py 
"""
import logging
import requests
import json
import string
import socket
import sys
import pprint
# --------------------------------------------
# Description: API Configurazione             |         
# --------------------------------------------

qtcBaseUrl      = 'https://192.168.179.230:5000/'
qtcCredential   = {'username':'drhouse', "password":"drhouse"}


# ------------------------------
# Description:                  
# -----------------------------
# @param 
# @return -
# ----------------------------- 
def qtcApiLogin(usr,pwd,APP_LOGGER):

    try :
  
        qtcLogin = requests.post("https://192.168.179.230:5000/login", 
            json = {'username': usr, "password": pwd}, 
            headers = {'Content-type': 'application/json'},
            verify=False
        )

        cookies = qtcLogin.cookies

        ret = {
            'success': True,
            'token': qtcLogin.json()['token'],
            'cookies':cookies
        }

        APP_LOGGER.debug("LOGIN: Token = " + qtcLogin.json()['token'] +"\n" )
        APP_LOGGER.debug("LOGIN: Cookies = " + str(cookies) + "\n" )

    except Exception as err:

        APP_LOGGER.error("Login qTC error:" +{err})
        
        ret = {'success':False}

    return qtcLogin

# ---------------------------------------
# Description: Funzione di logout da qTC                 
# ---------------------------------------
# @param  : qtcLogin. oggetto qtcLogin 
#           proveniente dalla chiamata 
#           alla funzione qtcLogin.

# @param  : APP_LOGGER. Oggetto logger 
#           dichiarato nel receiver.py
#
# @return : oggetto qtcLogout.
# ---------------------------------------
def qtcApiLogout(qtcLogin,APP_LOGGER):

    try:

        qtcLogout = requests.get("https://192.168.179.230:5000/logout",
                             headers= { 'Authorization': 'Bearer ' + qtcLogin.json()['token'] },
                             verify = False , cookies = qtcLogin.cookies)

        APP_LOGGER.info("qtcLogout") 

    except Exception as err:

        APP_LOGGER.info("Logout qTC error:" +{err})
  
    return qtcLogout

# ------------------------------
# Description:                  
# -----------------------------
# @param 
# @return -
# ----------------------------- 
def qtcApiExaminationCreate(qtcLogin,qtcExam,APP_LOGGER):
 
    APP_LOGGER.debug("\n\n *** qtcApiExaminationCreate *** \n") 

    APP_LOGGER.debug("qtcApiExaminationCreate - qtcExam = " + str(qtcExam))

    APP_LOGGER.debug("qtcApiExaminationCreate - token = " + str(qtcLogin.json()['token']))

    try:

        qtcExamCreate = requests.post("https://192.168.179.230:5000/examination/fetch", 
                            json=qtcExam, 
                            headers={'Content-type': 'application/json', 'Authorization': 'Bearer ' + qtcLogin.json()['token'] }, 
                            verify=False, cookies = qtcLogin.cookies )

        #APP_LOGGER.info("Create = " + str(qtcExamCreate.text))


    except Exception as err:
        
        print( f'Other error occurred: {err}' ) 

 
    return qtcExamCreate.json()

#------------------------------
# Description:                  
# -----------------------------
# @param 
# @return -
# ----------------------------- 
def qtcApiExaminationList(qtcLogin,APP_LOGGER):

    try:
        
        qtcExamList = requests.get("https://192.168.179.230:5000/examination",
                            headers= { 'Content-type': 'application/json', 
                                       'Authorization': 'Bearer ' + qtcLogin.json()['token'] },
                            verify=False, cookies=qtcLogin.cookies)

    #    APP_LOGGER.info("EXAMs: " + str((qtcExamList.json())))
        
        APP_LOGGER.info("EXAMs: " + str(qtcExamList.json()))
    
    except Exception as err:

        # come gestire questa eccezione?
        APP_LOGGER.info("ExamList qTC error:" +{err})
 
    return qtcExamList

#------------------------------
# Description:                  
# -----------------------------
# @param 
# @return -
# -----------------------------

def qtcApiExamSearch(qtcLogin,StudyInstanceUID,APP_LOGGER):

    ret = False

    APP_LOGGER.debug("qtcLogin123 = {}".format(qtcLogin.json()['token']))    
    APP_LOGGER.debug("StudyInstanceUID = {}".format(StudyInstanceUID))    

    try:

        qtcExamSearch = requests.post("https://192.168.179.230:5000/examination/search", 
            json={ 'clinical_question': StudyInstanceUID }, 
            headers={'Content-type': 'application/json', 'Authorization': 'Bearer ' + qtcLogin.json()['token'] }, 
            verify=False, cookies = qtcLogin.cookies 
        )

        fetchoutput=json.loads(qtcExamSearch.text)

        APP_LOGGER.debug(fetchoutput)

        return json.dumps({'success': True, 'data' : fetchoutput })

    except Exception as err:
        
        APP_LOGGER.error(f'Other error occurred: {err}')   
        
        return json.dumps({'success': False, 'message' : err })

    

