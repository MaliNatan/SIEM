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
    add_log = ("SELECT DISTINCT SRC_IP, DST_IP, PORT FROM fwlogs;")
    cursor.execute(add_log)
    dic={}
    for c in cursor:
        ip = c[0], ' to ', c[1]
        if ip in dic.keys():
            dic[ip]+=1
        else:
            dic[ip]=1
    for x in dic.iteritems():
        if x[1]>10:
            print "Find Port Scan attack from ", ''.join(x[0]), "to", x[1], "ports"
    cnx.commit()
    cursor.close()
    cnx.close()


def main():
    #SpecificPort()
    PortScan()

main()