from Parser import *


def SpecificPort():
    cnx, cursor = ConnectToDB()
    add_log = ("SELECT SRC_IP FROM fwlogs WHERE PORT=444 OR PORT=4445;")
    cursor.execute(add_log)
    list=[]
    for c in cursor:
        if c not in list:
            list.append(c)
    if len(list)>0:
        print "Find Specific Port attack from ports:\n", list
    else:
        print "No Specific Port attack"
    cnx.commit()
    cursor.close()
    cnx.close()



def PortScan():
    cnx, cursor = ConnectToDB()
    add_log = ("SELECT * FROM fwlogs;")
    cursor.execute(add_log)
    list1=[]
    for c in cursor:
        list1.append(c)
    list1=list(set(list1))
    for l in list1:
        print l
    #wprint list1
    cnx.commit()
    cursor.close()
    cnx.close()


def main():
    #SpecificPort()
    PortScan()

main()