import time
from datetime import date, timedelta
import mysql.connector
import csv
import os




addConnection = ("INSERT INTO Incoming_Data VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
csvPath = "/home/ec2-user/Incoming/Incoming_Data"

try:
    db = mysql.connector.connect(host='ipro-f22-db.crhoiczd7use.us-east-1.rds.amazonaws.com',   # Connects to MySQL server
                                  user='BackendAdmin',
                                  password='R0ckBack3nd!',
                                  database='backend')
    cursor = db.cursor()
    print("Connected")
    while True:
        fileList = os.listdir(csvPath)
        connections = 0
        while(fileList):
            with open(csvPath + "/" + fileList[0]) as csvfile:   # Opens csv file
                reader = csv.reader(csvfile)
                pcinfo = reader.__next__()  # [MAC, domain, user, timestamp]
                pcinfo[0] = pcinfo[0][2:]   # Gets rid of 0x in front of value
                # print(fileList[0])
                for line in reader:
                    connections += 1
                    sourceIP = line[2].rsplit(':', 1)
                    destIP = line[3].rsplit(':', 1)
                    connectionInfo = (pcinfo[0], line[1], sourceIP[0], sourceIP[1], destIP[0], destIP[1], pcinfo[1],
                                      pcinfo[2], pcinfo[3], line[4], line[0], line[5], "null")
                    cursor.execute(addConnection, connectionInfo)
                db.commit()
                print(fileList[0] + ' uploaded to database.')
                os.remove(csvPath + "/" + fileList[0])
                fileList.pop(0)
        # Update connection count and check if daily count needs to be reset
        today = date.today()
        unixdate = time.mktime(today.timetuple())
        cursor.execute("SELECT EXISTS (SELECT * FROM Stats WHERE Date = %s)", [unixdate])
        if cursor.fetchone()[0]: # Row does exist and needs to be updated
            cursor.execute("SELECT * FROM Stats WHERE Date = %s", [unixdate])
            stats = cursor.fetchone()
            newdata = (stats[0] + connections, stats[1] + connections, unixdate)
            #print(stats)
            #print(newdata)
            cursor.execute("UPDATE Stats SET Total_Connections=%s, Daily_Connections=%s WHERE Date=%s", newdata)
            db.commit() # Applies the changes made to the database
            print("Stats updated")

        else: # Row doesn't exist and needs to be created
            cursor.execute("SELECT * FROM Stats")
            oldStats = cursor.fetchall()[-1]
            newStats = (oldStats[0] + connections, connections, oldStats[2], 0, oldStats[4], 0, unixdate)
            cursor.execute("INSERT INTO Stats VALUES(%s, %s, %s, %s, %s, %s, %s)", newStats)
            db.commit() # Applies the changes made to the database
            print("created")

        time.sleep(5)
    cursor.close()
    db.close()
except mysql.connector.Error as error:
    print(error)
