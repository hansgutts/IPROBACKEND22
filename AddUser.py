from collections import UserList
import mysql.connector
import csv

#just print out whether it was succesful or not++


try:
    userExist = ("SELECT EXISTS (SELECT Username FROM `backend`.`Users` WHERE Username=%s)")    #this query checks to see if this username exists (1 if yes 0 if no)
    addUser = ("INSERT INTO backend.Users VALUES (%s, %s, %s)")
    db = mysql.connector.connect(host='ipro-f22-db.crhoiczd7use.us-east-1.rds.amazonaws.com',   #log in to database
                                  user='BackendAdmin',
                                  password='R0ckBack3nd!',
                                  database='backend')
    
    addUserCommand = db.cursor()
    userExistsCommand = db.cursor()

    with open('../Incoming/UserTest.csv') as csvfile:   #open csv and reference as csvfile
        reader = csv.reader(csvfile)
        user = reader.__next__()        #read all data into one variable
        csvfile.close()                 #close our connection to the file

        userExistsCommand.execute(userExist, [user[0]])     #execute command check to see if the username is already taken
        userList = userExistsCommand.fetchall()             #move this to a variable
        if ((userList[0])[0] == 0) :                        #the 1 or 0 is given as [(1,)] or [(0,)]. if username does not exist  
            addUserCommand.execute(addUser, user)           #create the user
            print("Success. User created.")

        else :
            print("Failed. User exists.")    #otherwise print error message

    db.commit()                                             #commit the changes
    addUserCommand.close()                                  #close connections
    userExistsCommand.close()
    db.close()
except mysql.connector.Error as error:
        print(error)
