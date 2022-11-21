import mysql.connector
import csv
import pandas as pd
#import aspose.words as aw
import requests
import time

from datetime import date

while(True) :
    print("Start")
    URL = "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts.deny/hosts0.deny"
    HOST_DENY_PATH = "HostDeny.txt"    #constants
    #MANUAL_DENY_PATH = "ManualDeny.txt"
    GET_SOURCE = ("SELECT Source_Address FROM `backend`.`Incoming_Data` WHERE Malicious != \"True\" AND Malicious !=\"False\"")               #get the source ips
    GET_DESTINATION = ("SELECT Destination_Address FROM `backend`.`Incoming_Data` WHERE Malicious != \"True\" AND Malicious != \"False\"")     #get the destination ips
    GET_INCOMING_DATA = ("SELECT * FROM Incoming_Data WHERE Source_Address = %s OR Destination_Address = %s")           #get the data from database
    UPDATE_MALICIOUS = ("UPDATE `backend`.`Incoming_Data` SET `Malicious` = %s WHERE (Source_Address = %s OR Destination_Address = %s) AND (Malicious != \"True\" AND Malicious !=\"False\")")            #update the malicious column
    UPDATE_ALL_TIME = ("UPDATE `backend`.`Stats` set `Total_Malicious_Hits_IP` = `Total_Malicious_Hits_IP` + %s WHERE Date = %s")   #update the all time malicious ip counter
    UPDATE_DAILY = ("UPDATE `backend`.`Stats` set `Daily_Malicious_IP` = `Daily_Malicious_IP` + %s WHERE Date = %s")    #update the daily malicious ip counter
    TODAY = str(time.mktime(date.today().timetuple()))

    try:
        db = mysql.connector.connect(host='ipro-f22-db.crhoiczd7use.us-east-1.rds.amazonaws.com',   #connect to database
                                    user='BackendAdmin',
                                    password='R0ckBack3nd!',
                                    database='backend')
        badips = []    #initalize array of bad ips

        getSourceCommand = db.cursor()          #our cursors
        getDestinationCommand = db.cursor()
        getIncomingDataCommand = db.cursor()
        updates = db.cursor()

        
        getDestinationCommand.execute(GET_DESTINATION)       #get destination ips from the database
        destinationips = getDestinationCommand.fetchall()
        getSourceCommand.execute(GET_SOURCE)                 #get source ips from the database
        sourceips = getSourceCommand.fetchall()

        alldirtyips = destinationips + sourceips                 #combine all the not yet cleaned up ips
        allips = []
        for ips in alldirtyips :                            #get the single ips out of a list
            allips.append(ips[0])                           #this gets us a cleaned up version of the ips

        #Pull raw file from github, basically a txt file
        
        download = requests.get(URL)

        deny = download.text.split('\n') #Split file by lines
        
        for line in deny :                              #for every line in our deny file
            if (not line.startswith('#')) :             #check to see if data or a comment
                splitline = line.split()                #if data, split into ["ALL:", ip address]
                if (splitline) :                        #make sure there is data (if not empty basically)
                    badips.append(splitline[1])         #add bad ips to array
            """with open(MANUAL_DENY_PATH) as manualdeny:      #if manual deny is a text file
                deny = manualdeny.read().splitlines()
                for line in deny :
                    badips.append(line)

            with open(MANUAL_DENY_PATH) as manualdeny:
                deny = csv.reader(manualdeny)
                for line in deny:
                    badips.append(line)"""

        foundips = []                                   #where we'll store the ips that are confirmed to be infected


                                                        #set the database entries to signify they are malicious. 
                                                        #We need to set the bad ones first so we dont override when we find a non malicious one
                                                        #since we use source and destination, we may say its not malicious before we even check the destination.3
        for ip in allips :                              #for all the ips, find out if bad and store it
            if (ip in badips) :
                updates.execute(UPDATE_MALICIOUS, ["True", ip, ip])  
                foundips.append(ip)
        for ip in allips :
            if (ip not in badips) :
                updates.execute(UPDATE_MALICIOUS, ["False", ip, ip])

        #update the count of our statistics MUST DO HERE BEFORE WE REMOVE DUPLICATES
        num = len(foundips)
        updates.execute(UPDATE_ALL_TIME, [num, TODAY])
        updates.execute(UPDATE_DAILY, [num, TODAY])

        foundips = list(set(foundips))                  #remove the duplicate found ips

        reportdata = []
        with open('../Outgoing/Outgoing_Data/BadIPs.csv', 'w', newline = '') as badipcsv :     #open the bad ip csv file
            writer = csv.writer(badipcsv) 
            if (foundips) :                             #if there exists bad ips
                for ip in foundips :
                    getIncomingDataCommand.execute(GET_INCOMING_DATA, [ip, ip])     #we want to return the row in database containing the bad ip
                    baddata = (getIncomingDataCommand.fetchall())
                    for bad in baddata :                    #when fetching, we may get multiple instances of the same ip address but on different machines
                        writer.writerow(bad)                #write the row into our csv
            


        db.commit()                     #commit the changes  
        getSourceCommand.close()        #close connections
        getDestinationCommand.close()
        getIncomingDataCommand.close()
        updates.close()
    except Exception as e:
        print(e)
        print("There was an error")
    print("done")
    time.sleep(30)