import mysql.connector
import csv
import os
import sys
import time

dirLogin = "/home/ec2-user/Incoming/Login/"
#dirLogin = "C:\\Users\\lilde\\Desktop\\loginfiles\\" ##testpath
user = []
tempUser = {}
mac = sys.argv[1]


login = dirLogin + mac + 'login.csv'
print(login)
##Connect to Database
try:
    cnx = mysql.connector.connect(user='BackendAdmin', password='R0ckBack3nd!',
        host='ipro-f22-db.crhoiczd7use.us-east-1.rds.amazonaws.com',
        database='backend')
    print("Connection Established")
except:
    print("Connection Failed")

##Place user info in array for ease of access
with open(login, 'r') as file:
    user = list(csv.reader(file))
print(user)
##Check user info against database and create response file
cursor = cnx.cursor(buffered = True, dictionary = True)
query = " SELECT * FROM Users Where Username = '%s' " % user[0][0]
cursor.execute(query)
tempUser = cursor.fetchone()
print(tempUser)
if (tempUser == None or user[0][1] != tempUser['Passcode']):
    print("login failed")
    loginOut = '/home/ec2-user/Outgoing/Login/' + mac + 'fail.txt'
    #loginFail = 'C:\\Users\\lilde\\Desktop\\loginfiles\\report\\' + mac + 'fail.txt' ##testpath
    with open(loginOut, 'w') as f2:
        f2.write(mac + ' login failure')
    #Wait for frontend to grab file
    time.sleep(4)
else:
    print("login success")
    loginOut = '/home/ec2-user/Outgoing/Login/' + mac + 'success.txt'
    #loginSuccess = 'C:\\Users\\lilde\\Desktop\\loginfiles\\report\\' + mac + 'success.txt' ##testpath
    with open(loginOut, 'w') as f1:
        string = mac + ' login success, access level: %s' % tempUser['Access_Level']
        f1.write(string)
    #Wait for frontend to grab file
    time.sleep(4)

cursor.close()
cnx.close()

#Remove login file and reports after service completion
if (os.path.exists(login)):
    os.remove(login)
if (os.path.exists(loginOut)):
    os.remove(loginOut)
#elif loginFail is not None and (os.path.exists(loginFail)):
#    os.remove(loginFail)
