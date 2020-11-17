import logging
import pprint
from datetime import datetime
from qtc.api2 import *
import daiquiri

def setup_logger():
    logger      = logging.Logger('core_qtc')
    handler     = logging.StreamHandler()
    formatter   = logging.Formatter('%(levelname)s (%(name)s): %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

qtcLogger = setup_logger()

class qtcError(Exception):
    pass


#----------------------------------------------------
# Description:  Costruzione del corpo di un esame qTC               
# ---------------------------------------------------
# @param 
# @return -
# ---------------------------------------------------
def qtcExamBuild(  pN, deidExam, qtcClinicOid ):

    qtcLogger.debug("qtcExamBuild...")

    currentDateTime = datetime.now()

    qtcExam = {  
            
        "patient_data": {

            "first_name"    : pN, 
            "last_name"     : "XXX", 
            "birthdate"     : deidExam['patient']['patientBirthDate'],
            "birthplace"    : "XXX", # Comune di nascita - non presente in DICOM 
            "gender"        : deidExam['patient']['gender'],
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
            "modality"              : deidExam['modality'],
            "service_type"          :"PRIVATO",
            #"anamnesis"             :"Anamnesi" # DA INSERIRE DAL MEDICO INVIANTE SU INTERFACCIA
        }
    }

    # Caso in cui ci sia il tag ma è vuoto -> Default = M!
    if  qtcExam["patient_data"]["gender"] == "":
        qtcExam["patient_data"]["gender"] = "M"

    qtcLogger.debug("examBuild = " + str(qtcExam))
    qtcLogger.debug("examBuild...Finish")

    return qtcExam


#-------------------------------------------
# Description:                
# ------------------------------------------
# @param 
# @return -
# ------------------------------------------

def qtcExamCreate ( qtcLogin,  qtcBuild, studyInstanceUID ):

    qtcLogger.debug("qtcExamCreate...Start")

    # Call qTC API 
    examCreate = qtcApiExaminationCreate(qtcLogin,qtcBuild,qtcLogger)

    # Handle the request
    if ( examCreate['code'] == 300 ) and ( examCreate['message'] == "Examination correctly created!" ):
       
        qtcLogger.info("StudyInstanceUID = " + studyInstanceUID + " -> CREATED in qTC (" 
                        + qtcBuild['patient_data']['first_name'] +")" )
        
        qtcLogger.debug("examCreate...Finish True")
        return True
    
    else:
        
        qtcLogger.info("StudyInstanceUID = " + studyInstanceUID + " -> UNABLE to CREATE in qTC")
        qtcLogger.debug("examCreate...Finish False")
        return False    
        
#-------------------------------------------
# Description:                
# ------------------------------------------
# @param 
# @return :   True: if exist / False if not exist
# ------------------------------------------

def qtcExamExist (  qtcLogin, StudyInstanceUID ):

    qtcLogger.debug("qtcExamExist {}...Start".format(StudyInstanceUID))

    # Call qTC API 
    examSearch  = qtcApiExamSearch (qtcLogin, StudyInstanceUID, qtcLogger)

    # Json -> dict 
    examSearch = json.loads(examSearch)

    qtcLogger.debug("examSearch = {}".format(examSearch))

    # Handle the request
    if ( examSearch['success'] == True ) and ( examSearch['data']['code'] == 301 ) : 

        qtcLogger.info("StudyInstanceUID = " + StudyInstanceUID + " -> NOT EXIST in qTC!")
        return False

    elif ( examSearch['success'] == True ) and ( examSearch['data']['code'] == 300 ):    

        qtcLogger.info("StudyInstanceUID = " + StudyInstanceUID + " -> ALREADY EXIST in qTC!")
        return True

    else:
        qtcLogger.info("pass")
        pass

#-------------------------------------------
# Description:                
# ------------------------------------------
# @param 
# @return -
# ------------------------------------------

def qtcClinicExist ( qtcLogin, callingAETitle ):

    qtcLogger.debug("qtcClinicExist {}...Start".format(callingAETitle))

     # Call qTC API 
    clinicSearch  = qtcApiClinicSearch (qtcLogin, callingAETitle, qtcLogger)

    clinicSearch = json.loads(clinicSearch)

    # qtcLogger.info(f"qtcClinic = {clinicSearch}")

    # Handle the request
    if ( clinicSearch['success'] == True ) and ( clinicSearch['data']['code'] == 200 ) : 

        qtcClinicOid = clinicSearch['data']['data'][0]['_id']['$oid']

        qtcLogger.info(f"Clinic: {callingAETitle} -> FOUNDED in qTC (oid={qtcClinicOid}) " )
        
        return qtcClinicOid 

    elif ( clinicSearch['success'] == True ) and ( clinicSearch['data']['code'] == 201 ):    

        qtcLogger.info( "Clinic {} -> NOT FOUNDED in qTC ".format(callingAETitle) )

        return None
 
    else:
        qtcLogger.info("qtcClinicExist Error")

