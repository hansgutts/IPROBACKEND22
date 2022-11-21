import mysql.connector

HOST_DENY_PATH = "Host_Deny.txt"    #constants
GET_SOURCE = ("SELECT Source_Address FROM `backend`.`Incoming_Data`")
GET_DESTINATION = ("SELECT Destination_Address FROM `backend`.`Incoming_Data`")

try:
    db = mysql.connector.connect(host='ipro-f22-db.crhoiczd7use.us-east-1.rds.amazonaws.com',   #connect to database
                                  user='BackendAdmin',
                                  password='R0ckBack3nd!',
                                  database='backend')
    badips = []    #initalize array of bad ips
    with open(HOST_DENY_PATH) as hostdeny:  #read the hostdeny file
        
        cursor = db.cursor()

        print("its open")
        #with open(manualdenypath) as manualdeny:
        deny = hostdeny.read().splitlines()             #read the lines for the file and split to get rid of /n
        for line in deny :                              #for every line in our deny file
            if (not line.startswith('#')) :             #check to see if data or a comment
                splitline = line.split()                #if data, split into ["ALL:", ip address]
                if (splitline) :                        #make sure there is data (if not empty basically)
                    badips.append(splitline[1])         #add bad ips to array
        hostdeny.close()                                #close connections
        print("Connection closed")
except Exception as e:
    print(e)
