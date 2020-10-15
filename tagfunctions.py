

def keeptag(tag, dataset):
    pass


def passtag(tag, dataset):
    pass


def modifyUID(tag, dataset): #come implementare hash?
    from pydicom.uid import generate_uid
    dataset[tag].value=generate_uid()
        # pydicom.uid.generate_uid(prefix='1.2.826.0.1.3680043.8.498.', entropy_srcs=None)[source]
    # Return a 64 character UID which starts with prefix.
    # Changed in version 1.3: When prefix is None a conformant UUID suffix of up to 39 characters will be used instead of a hashed value.
    # Parameters
            # prefix (str or None) – The UID prefix to use when creating the UID. Default is the pydicom root UID '1.2.826.0.1.3680043.8.498.'. If None then a prefix of '2.25.' will be used with the integer form of a UUID generated using the uuid.uuid4() algorithm.
            # entropy_srcs (list of str or None) – If prefix is not None, then prefix will be appended with a SHA512 hash of the list which means the result is deterministic and should make the original data unrecoverable. If None random data will be used (default).


def modifydate(tag, dataset):
    from datetime import date, timedelta
    newdate = date(int(dataset[tag][0:4]), int(dataset[tag].value[4:6]), int(dataset[tag].value[6:8]))
    dateInterval = int(dataset[0x001310ff].value)
    dataset[tag].value = (newdate + timedelta(days = dateInterval)).strftime('%Y%m%d')
    #Attenzione: aggiungendo si potrebbe andare in data futura.
    #In più, abbiamo cercato di allontanarci il più possibile dalla data reale.

def cleartag(tag, dataset):
    dataset[tag].value = ''


def removetag(tag, dataset):
    del dataset[tag]


def assignBCUID(tag, dataset): 
    tagMap = {
        'PatientName': 0x001310fd,
        'PatientID': 0x001310fd,
        'InstitutionName': 0x001310fe,
    }
    dataset[tag].value = dataset[tagMap[tag]].value


#def assignStudyID(tag, dataset):
    #dataset[tag].value='BCU_SID000001'
    #da verificare/implementare. Serve DB o file da leggere
    # if dataset[tag].value in registroBCU: dataset[tag].value = SELECT chiaveBCU FROM registroBCU WHERE studyID=dataset[tag] #attenzione, potrebbe essere 
    # else dataset[tag].value = 'BCU_S'+ ( SELECT MAX(id)+1 FROM chiavi )


def compiletag(tag, dataset):
    pass


# def addtag(tag, dataset):


    # if tag == 'PatientIdentifiedRemoved': dataset.add_new([0x0012,0x0062],'CS','YES')
    # elif tag=='DeidentificationMethod': dataset.add_new([0x0012,0x0063],'LO', method) #metodo
    # elif tag=='DeidentificationMethodCodeSQ': dataset.add_new([0x0012,0x0064],'SQ', code) #codici
