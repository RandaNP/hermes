"""
qtc/core.py 
"""

import logging
import pprint
from datetime import datetime
from qtc.api2 import *

#-------------------------------------------
# Description:  Costruzione di un esame qTC               
# ------------------------------------------
# @param 
# @return -
# ------------------------------------------

def qtcExamBuild(  pN,
                deidExam,
                qtcClinicOid,
                ds,
                APP_LOGGER  
):
    APP_LOGGER.debug("qtcExamBuild...")

    currentDateTime = datetime.now()

    qtcExam = {  
            
        "patient_data": {

            "first_name"    : pN, 
            "last_name"     : "XXX", 
            "birthdate"     : deidExam['patient']['patientBirthDate'],
            "birthplace"    : "XXX", # Comune di nascita - non presente in DICOM 
            "gender"        : ds.get("PatientSex","M"),
            "phone_number"  : "XXX" 
        },

        "examination_data": {   

            "date_creation"         : currentDateTime.strftime('%Y-%m-%d %H:%M:%S'),
            "date_upload"           : currentDateTime.strftime('%Y-%m-%d %H:%M:%S'), 
            "clinical_date"         : '-'.join([deidExam['studyDate'][0:4],
                                                deidExam['studyDate'][4:6],
                                                deidExam['studyDate'][6:8]]) + " 00:00:00",
            "clinic_fkid"           : qtcClinicOid,
            "clinical_code"         : [""], # DA INSERIRE DAL MEDICO INVIANTE SU INTERFACCIA
            "patient_id_DICOM"      : deidExam['patient']['bcuPatientID'],
            "clinical_question"     : deidExam['studyInstanceUID'],
            #"diagnostic_question"   :"Referto", # DA INSERIRE DAL MEDICO INVIANTE SU INTERFACCIA
            "modality"              : ds.get("Modality", ''),
            "service_type"          :"PRIVATO",
            #"anamnesis"             :"Anamnesi" # DA INSERIRE DAL MEDICO INVIANTE SU INTERFACCIA
        }
    }

    # Caso in cui ci sia il tag ma è vuoto -> Default = M!
    if  qtcExam["patient_data"]["gender"] == "":
        qtcExam["patient_data"]["gender"] = "M"

    APP_LOGGER.debug("examBuild = " + str(qtcExam))
    APP_LOGGER.debug("examBuild...Finish")

    return qtcExam


#-------------------------------------------
# Description:                
# ------------------------------------------
# @param 
# @return -
# ------------------------------------------

def qtcExamCreate ( qtcLogin, 
                    qtcBuild,
                    ds, 
                    APP_LOGGER
):

    APP_LOGGER.debug("qtcExamCreate...Start")

    # Call qTC API 
    examCreate = qtcApiExaminationCreate(qtcLogin,qtcBuild,APP_LOGGER)

    # Handle the request
    if ( examCreate['code'] == 300 ) and ( examCreate['message'] == "Examination correctly created!" ):
       
        APP_LOGGER.info("StudyInstanceUID = " + ds.StudyInstanceUID + " -> CREATED in qTC (" 
                        + qtcBuild['patient_data']['first_name'] +")" )
        
        APP_LOGGER.debug("examCreate...Finish True")
        return True
    
    else:
        
        APP_LOGGER.info("StudyInstanceUID = " + ds.StudyInstanceUID + " -> UNABLE to CREATE in qTC")
        APP_LOGGER.debug("examCreate...Finish False")
        return False    
        
#-------------------------------------------
# Description:                
# ------------------------------------------
# @param 
# @return :   True: if exist / False if not exist
# ------------------------------------------

def qtcExamExist (  qtcLogin, 
                    StudyInstanceUID, 
                    APP_LOGGER
):

    APP_LOGGER.debug("qtcExamExist {}...Start".format(StudyInstanceUID))

    # Call qTC API 
    examSearch  = qtcApiExamSearch (qtcLogin, StudyInstanceUID, APP_LOGGER)

    # Json -> dict 
    examSearch = json.loads(examSearch)

    APP_LOGGER.debug("examSearch = {}".format(examSearch))

    # Handle the request
    if ( examSearch['success'] == True ) and ( examSearch['data']['code'] == 301 ) : 

        APP_LOGGER.info("StudyInstanceUID = " + StudyInstanceUID + " -> NOT EXIST in qTC!")
        return False

    elif ( examSearch['success'] == True ) and ( examSearch['data']['code'] == 300 ):    

        APP_LOGGER.info("StudyInstanceUID = " + StudyInstanceUID + " -> ALREADY EXIST in qTC!")
        return True

    else:
        APP_LOGGER.info("pass")
        pass

