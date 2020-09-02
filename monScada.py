import time
import random
import datetime
import os
import psutil
import string


#Simulate SCADA data generation process
#3 tags simulating sensor reads

def DataSimulator():
    
    scadaFile = open('data/scadatags.txt','a+')
    nOffSet = 0.00000

    for x in range(0,1000000):
        time.sleep(0.25)

        #Check for Flag in Control File 0 = Normal; 1  = System Malfunction
        controlFile = open('data/attack.txt','r')
        cScadaState = controlFile.read()
        controlFile.close()
        

        #If Simulation is flagged for Malfunction, Normal Meassures are offset from 25% to 100% above normal ranges
        if int(cScadaState) == 1:
            nOffSet = float(random.randrange(25,100)/float(100))
        else:
            nOffSet = 0.000000
        
        #Simulate Temperature Sensor. Normal Operation Range 94-96 F
        nSensor = random.randrange(94,95)+(random.randrange(1,10)/float(10))
        nSensor = nSensor + (nOffSet * nSensor)
        cTemperature ='V3130\t'+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' |LONG |TEMP\tLUBRIC\tFAREN\t'+str(nSensor)
        scadaFile.write(cTemperature+'\n')
        print(cTemperature)

        #Simulate Pressure Sensor. Normal Operation Range 235-250 psi.
        nSensor = random.randrange(235,249)+(random.randrange(1,10)/float(10))
        nSensor = nSensor + (nOffSet * nSensor)
        cPressure = 'V3114\t'+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' |LONG |BARS\tPRESSR\tmmOWB\t'+str(nSensor)
        scadaFile.write(cPressure+'\n')
        print(cPressure)

        #Simulate Main Turbine Electric Flow. Normal Operation Range 850-950 AMP
        nSensor = random.randrange(850,949)+(random.randrange(1,10)/float(10))
        nSensor = nSensor + (nOffSet * nSensor)
        cCurrent = 'V3450\t'+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' |LONG |POWR\tTORQUE\tAMPER\t'+str(nSensor)
        scadaFile.write(cCurrent+'\n')
        print(cCurrent)

        scadaFile.flush()


        
    scadaFile.close()
    return

# Reads Input from data file and evaluate the behavior
# of the sensor meassures. When a sensor read is out of
# range FORENSIC LOG is triggered until all operations get
# back to normal.

def monitorSCADA():

    scadaMonitor = open('data/scadatags.txt','r')
    fileState = os.stat('data/scadatags.txt')
    fileSize = fileState[6]
    scadaMonitor.seek(fileSize)

    #Monitors the growth on the scadatags file and fetchs the new lines
    while 1:
        where = scadaMonitor.tell()
        cline = scadaMonitor.readline()
        if not cline:
            cSystem = str(psutil.cpu_percent(interval=0.3))
            print("SYSTEM STATE: NORMAL CPU % USAGE: "+cSystem+" WAITING FOR NEW DATA")
            time.sleep(1)
            scadaMonitor.seek(where)
        else:
            
            
            #print('Forensic Log: STARTED ON:'+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' Sensor: '+cSensorVar+' READS - '+cSensorData.rstrip(' ALERT\r\n'))

            #Strip out data from the scadatag string 
            cSensorData = cline[cline.rfind('\t')+1:]
            cSensorVar = cline[:5]
            cSensorRecord = find_sensors(cSensorVar)
            nMinRange = int(cSensorRecord[6:9])
            nMaxRange = int(cSensorRecord[10:13])

            #Evaluate Sensor Measure Range
            if float(cSensorData) < nMinRange or float(cSensorData) > nMaxRange:
                #Activate Forensic Log
                cSystem = str(psutil.cpu_percent(interval=0.3))
                print("SYSTEM MALFUNCTION - DUMPING SYSTEM STATE TO Forensic Log ... CPU %"+cSystem)
                #Start Dumping for Scada Variables and System Performance Variables
               
                #clogStr = ('Forensic Activity Logged at:'+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' Sensor: '+cSensorVar+' READS - '+cSensorData.rstrip(' ALERT\r\n'))
                
                dump_tolog(cSystem,cSensorVar,cSensorData)
                
            else:
                print("SYSTEM STATE: NORMAL CPU % USAGE: "+cSystem+" SENSOR VALUES - OK")
                      

    return


def dump_tolog(cCpu,cSensor,cData):
    
    logFile =open("data/ForensicLog.txt",'a+')
    
    cPhyMem = psutil.phymem_usage()
    cVirMem = psutil.virtmem_usage()
    cNetTraffic = psutil.network_io_counters(pernic=True)
    cPartitionInfo = psutil.disk_partitions()
    cActiveProcess =''
            
    logFile.write('*===================================================*'+'\n')
    logFile.write('|Forensic Activity Logged at: '+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+'\n')
    logFile.write('*===================================================*'+'\n')
    logFile.write('SYSCOND:  MALFUNCTION | CPU LOAD: '+ cCpu+'% | SENSOR: '+cSensor+' | READ: '+cData+'\n')    
    logFile.write('PHYSICAL MEMORY:\n'+str(cPhyMem)+'\n\n')                                                   
    logFile.write('VIRTUAL MEMORY :\n'+str(cVirMem)+'\n\n')                                                  
    logFile.write('NETWORK STATUS :\n'+str(cNetTraffic)+'\n\n')
    logFile.write('MOUNTED DISKS  :\n'+str(cPartitionInfo)+'\n\n')
    logFile.write('PROCESS LIST   :\n')

    for proc in psutil.process_iter():
        logFile.write(str(proc)+',')

    logFile.write('\n')
    logFile.close()

    return

##def log_forensics():
##    #Create a new file for every event series
##    cLogName = randon_name()
##    logFile = open(cLogname+'.txt','w+')
##      
##    return

#Generate random names for Log Files
def random_name():
    char_set = string.ascii_uppercase + string.digits
    cRandomName = ''.join(random.sample(char_set,6))
    return cRandomName

#Lookup Sensor Tags in File containing range of values
def find_sensors(cSensor):
    sensorsFile = file('data/sensors.txt','r')
    for cline in sensorsFile:
        if cSensor in cline:
            cRecord = cline
    sensorsFile.close()
    return cRecord
