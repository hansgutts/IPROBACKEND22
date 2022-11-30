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
    GET_VALUES = ("SELECT Source_Address, Destination_Address, Source_Port, Destination_Port FROM `backend`.`Incoming_Data` WHERE Malicious != \"True\" AND Malicious !=\"False\"")
    GET_INCOMING_DATA = ("SELECT * FROM Incoming_Data WHERE Source_Address = %s AND Destination_Address = %s AND Source_Port = %s AND Destination_Port = %s")           #get the data from database
    UPDATE_MALICIOUS = ("""UPDATE `backend`.`Incoming_Data` SET `Malicious` = %s WHERE (Source_Address = %s AND Destination_Address = %s AND Source_Port = %s AND Destination_Port = %s) 
                        AND (Malicious != \"True\" AND Malicious !=\"False\")""")            #update the malicious column
    UPDATE_ALL_TIME = ("""UPDATE `backend`.`Stats` SET `Total_Malicious_Hits_IP` = `Total_Malicious_Hits_IP` + %s,
                                                       `Total_Malicious_Hits_Port` = `Total_Malicious_Hits_Port` + %s WHERE Date = %s""")   #update the all time malicious ip counter
    UPDATE_DAILY = ("""UPDATE `backend`.`Stats` SET `Daily_Malicious_IP` = `Daily_Malicious_IP` + %s, 
                                                    `Daily_Malicious_Port` = `Daily_Malicious_Port` + %s WHERE  Date = %s""")    #update the daily malicious ip counter
    TODAY = str(time.mktime(date.today().timetuple()))
    #print(TODAY)

    try:
        db = mysql.connector.connect(host='ipro-f22-db.crhoiczd7use.us-east-1.rds.amazonaws.com',   #connect to database
                                    user='BackendAdmin',
                                    password='R0ckBack3nd!',
                                    database='backend')
        badips = []    #initalize array of bad ips and ports
        badports = ["3389", "20", "23", "110", "143", "3306", "8080", "1433", "9200", "9300", "25", "445", "135", "21", "1434", "4333", "5432", "5500", "5601", "22", "3000", "5000", "8088"] 

        getValuesCommand = db.cursor()          #our cursors
        getIncomingDataCommand = db.cursor()
        updates = db.cursor()

        
        getValuesCommand.execute(GET_VALUES)       #get ips and ports from database
        values = getValuesCommand.fetchall()       #put them in one list [sourceip, destip, sourceport, destport]

        
        download = requests.get(URL)                #Pull raw file from github, basically a txt file

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

        foundvals = []                                   #where we'll store the values that are confirmed to be infected
        ips = 0                                          #the number of bad ips
        ports = 0                                        #the number of bad ports

                                                        
        for vals in values :                              #we need to go through values and find out if they're malicious
            tempports = 0                                 #increment this if they are, depending on port/ip value
            tempips = 0
            if (vals[0] in badips) :                      #compare the source and destination independently as they both signify individual malicious activity
                tempips += 1
            if (vals[1] in badips) :
                tempips += 1
            if (vals[2] in badports) : 
                tempports += 1
            if (vals[3] in badports) :
                tempports += 1
            if (tempips or tempports) :                   #after checking if malicious, if the values are anything but 0 they were malicious
                updates.execute(UPDATE_MALICIOUS, ["True", vals[0], vals[1], vals[2], vals[3]])   #update database based on all 4 values (using all 4 four to be careful)
                foundvals.append(vals)                                                            #store the bad ones
                ips += tempips                                                                    #store how many were bad
                ports += tempports
            else :
                updates.execute(UPDATE_MALICIOUS, ["False", vals[0], vals[1], vals[2], vals[3]]) #if we make it here, they were not malicious so update accordingly

        #update the count of our statistics MUST DO HERE BEFORE WE REMOVE DUPLICATES
        updates.execute(UPDATE_ALL_TIME, [ips, ports, TODAY])                                     #change the stats based on what we found
        updates.execute(UPDATE_DAILY, [ips, ports, TODAY])

        foundvals = list(set(foundvals))                  #remove the duplicate found values

        #create the file with the bad values
        baddata = []
        with open('../Outgoing/Outgoing_Data/BadIPs.csv', 'a', newline = '') as badipcsv :     #open the bad ip csv file
            writer = csv.writer(badipcsv) 
            if (foundvals) :                             #if there exists bad ips
                for vals in foundvals :
                    #print(vals)
                    getIncomingDataCommand.execute(GET_INCOMING_DATA, [vals[0], vals[1], vals[2], vals[3]])     #we want to return the row in database containing the bad ip/ports
                    bad = (getIncomingDataCommand.fetchall())
                    baddata.append(bad)
                for bad in baddata :                    #when fetching, we may get multiple instances of the same ip address but on different machines
                    print(bad)
                    writer.writerow(bad[0])                #write the row into our csv
            


        db.commit()                     #commit the changes  
        getValuesCommand.close()        #close connections
        getIncomingDataCommand.close()
        updates.close()
    except Exception as e:
        print(e)
        print("There was an error")
    print("done")
    time.sleep(30)