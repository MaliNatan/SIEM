PORTS = {'21' : 'FTP', '22' : 'SSH', '23' : 'TELNET', '25' : 'SMTP' , '67' : 'DHCP' , '53'  : 'DNS' , '80' : 'HTTP', '445'
: 'SMB' ,'443' : 'HTTPS'}

import mysql.connector
from mysql.connector import errorcode

user = 'root' 
password = 'P@ssw0rd'
host = '192.168.139.134'
database = 'siem'



def LogToDic(line):
    list=line.split(' ')
    dic={}
    dic['SRC_IP']=list[2]
    dic['ACTION']=list[5]
    dic['DATE']=list[0]+' '+list[1]
    dic['DST_IP']=list[3]
    dic['PORT']=list[4]
    return dic

def PortToProto(port):
    if port in PORTS.keys():
        return PORTS[port]
    else:
        return 'UNKNOWN'

def AddProto(line):
    dic=LogToDic(line)
    dic['PROTOCOL']=PortToProto(dic['PORT'])
    return dic

def ConnectToDB():
    try:
        cnx = mysql.connector.connect(user=user, password=password,
                                      host=host, database=database)
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None


def DicToDB(dic):
    cnx, cursor = ConnectToDB()
    add_log = ("""INSERT INTO fwlogs (ID, date, SRC_IP, DST_IP, PORT, PROTOCOL, ACTION) VALUES (NULL, %(DATE)s, %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)""")
    cursor.execute(add_log, dic)
    cnx.commit()
    cursor.close()
    cnx.close()

'''def AnalyzeSusPort():
    cnx, cursor=ConnectToDB()
    query=("SELECT SRC_IP FROM logs WHERE PORT IN ({})".format(','))
    cursor.execute(query)
    query_result=[]
    for line in cursor:
        query_result.append(line[0])
    cursor.close()
    cnx.close()
    return set(query_result)'''

def AllLogsToDB(log):
    new_log=open(log, 'r')
    for line in new_log:
        DicToDB(AddProto(line))



def main():
    line='2018-4-21 19:42:41 192.168.1.1 192.168.2.100 445 PASS'
    #print LogToDic(line)
    #print PortToProto('70')
    print AddProto(line)
    #DicToDB(AddProto(line))
    AllLogsToDB('C:\Users\Owner\Downloads\Drive\python\siem\Port_Scan.txt')

main()