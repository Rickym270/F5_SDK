#!/path/to/python3

from f5.bigip import ManagementRoot
from f5.bigip import BigIP
from f5.utils.responses.handlers import Stats

import netrc
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import sys
import os

from multiprocessing import Manager, Process

from datetime import datetime

start = datetime.now()

def _resolve_route_domain(ip, rd, session):
    '''
        Translate Route Domain (RD) ID's into their corresponding name.
        @params:
            ip      : f5 Device IP - Used for ReST calls.
            rd      : Used to match to find relavant RD name
            session : Session to make ReSTful calls.

        returns: rd_name - Returns the corresponding name.
    '''

    uri = "https://{}/mgmt/tm/net/route-domain?$select=name,id".format(ip)
    try:
        rd_res = session.get(uri, timeout=5,verify=False)
        rd_res = rd_res.json()
        rd_res = rd_res['items']
    except Exception as e:
        rd_res = None
        print("ERROR! {}".format(e))

    for domain in rd_res:
        rd_id = str(domain['id'])
        rd_name = domain['name']

        if rd_id == rd:
            return rd_name

def GetDeviceInfo(f5_Device_ip, f5_hostname = False, FileName = True):
    result = {'data':[]}

    if f5_Device_ip:
        # Get credentials from netrc file
        information = netrc.netrc('/path/to/.netrc').authenticators(f5_Device_ip)

        if information is not None:
            username = information[0]
            password = information[2]

            try:
                s = requests.Session()
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

                s.auth = (username, password)
            except Exception as e:
                s = None
                raise Exception("Unable to open a requests session: {}".format(e))

    if f5_hostname:
        # Get VIP Information
        print("Getting information for {}:{}({})...".format(f5_hostname[:2], f5_Device_ip, f5_hostname), end = "")
    else:
        print("Getting information for {}...".format(f5_Device_ip), end = "")

    try:
        # Connect to the BigIP
        bigip = BigIP("{}".format(f5_Device_ip), username, password)
    except Exception as e:
        print("Failed to connect to BigIP({}): {}".format(f5_Device_ip, e))
        raise Exception("Failed to connect to BigIP({}): {}".format(f5_Device_ip, e))

    # Get a list of all pools on the BigIP and print their name and their
    # members' name
    pools = bigip.ltm.pools.get_collection()
    virtuals = bigip.ltm.virtuals.get_collection()

    # Manually get iRules
    vip_res = s.get("https://{}/mgmt/tm/ltm/virtual/?$select=name,pool,rules".format(f5_Device_ip), timeout=5, verify=False)
    vip_response = vip_res.json()

    old_ip = ''
    for virtual in virtuals:
        # iterate through virtuals and get their info
        virtual_stats = Stats(virtual.stats.load())
        VIPName = virtual_stats.stat.tmName.description.replace('/Common/','')
        VIP_IP, VIP_Port = virtual_stats.stat.destination.description.split(':')

        try:
            VIP_IP, VIP_RD = VIP_IP.split('%')
            VIP_RD = _resolve_route_domain(f5_Device_ip,VIP_RD, s)
            old_ip = VIP_IP
        except Exception as e:
            VIP_RD = "N/A"

        VIP_EState = virtual_stats.stat.status_enabledState.description
        VIP_AState = virtual_stats.stat.status_availabilityState.description
        assoc_pool = "None"

        # Get the pool that the is associated with vips

        for i in range(0, len(vip_response['items'])):
            response_name = vip_response['items'][i].get('name')
            if response_name == VIPName:
                assoc_pool = vip_response['items'][i].get('pool')
                if assoc_pool is not None:
                    #NOTE: This is subject to change when we talk to the UK
                    assoc_pool = assoc_pool.replace('/Common/','')
                if assoc_pool is None:
                    assoc_pool = "None"
                continue;

        result['data'].append({
            'Hostname'          :   f5_hostname,
            'Host_IP'           :   f5_Device_ip,
            'VIP_Name'          :   VIPName,
            'VIP_IP'            :   VIP_IP,
            'VIP_Port'          :   VIP_Port,
            'VIP_RD'            :   VIP_RD,
            'VIPReason'         :   virtual_stats.stat.status_statusReason.description,
            'VIP_EState'        :   VIP_EState,
            'VIP_AState'        :   VIP_AState,
            'Default_Pool'      :   assoc_pool,
        })

    for pool in pools:
        # iterate through pools
        pool_stats = Stats(pool.stats.load())

        for vip in result["data"]:
            if vip["Default_Pool"] or vip["Default_Pool"]!="None":
                if vip["Default_Pool"] == pool.name:
                    # VIP has been associated with a pool
                    try:
                        old_member_ip = ''
                        for member in pool.members_s.get_collection():
                            # iterate trhough the members in the pool
                            member_stats = Stats(member.stats.load())

                            if not 'Members' in vip:
                                vip['Members'] = []

                            try:
                                member_ip, member_rd = member_stats.stat.addr.description.split('%')
                                if member_rd and member_ip != old_member_ip:
                                    member_rd = _resolve_route_domain(f5_Device_ip,member_rd, s)

                                    old_member_rd = member_rd
                            except Exception as e:
                                print("Member RD is non existent: {}... setting to 'N/A'".format(e))
                                member_ip = member_stats.stat.addr.description
                                member_rd = "N/A"

                                if '%' in member_ip:
                                    member_ip = member_stats.stat.addr.description.split('%')[0]
                                    member_rd = member_stats.stat.addr.description.split('%')[1]
                            print("VIP Name: {}, Member Name: {}, Member A-State: {}".format(vip['VIP_Name'], member.name.split(':')[0], member_stats.stat.status_availabilityState.description))

                            vip['Members'].append({
                                'MemberReason'      :   member_stats.stat.status_statusReason.description,
                                'MemberName'        :   member.name.split(':')[0],
                                'MemberIP'          :   member_ip,
                                'MemberRD'          :   member_rd,
                                'MemberPort'        :   member_stats.stat.port.value,
                                'MemberEState'      :   member_stats.stat.status_enabledState.description,
                                'MemberAState'      :   member_stats.stat.status_availabilityState.description,
                            })
                    except Exception as e:
                        print("\n\nError getting member info: {}\n\n".format(e))
                        member_res = "None"
                        member_response = "None"
                        member_uri = "None"
                        member_name = "None"
                        member_ip = "None"
                        member_port = "None"
                        member_rd = "None"
                        member_availState = "Unknown"
                        member_enabledState = "Unknown"
                        member_statusReason = "None"

                        #Add pool/member information to dict
                        if not "member" in vip:
                            vip["member"]= []
                        vip["member"].append({
                            "MemberName"    :   member_name,
                            "MemberIP"      :   member_ip,
                            "MemberPort"    :   member_port,
                            "MemberRD"      :   member_rd,
                            "MemberAState"  :   member_availState,
                            "MemberEState"  :   member_enabledState,
                            "MemberReason"  :   member_statusReason
                        })
                        print("Unable to get/no member information for {} -> {}".format(f5_Device_ip, default_pool))
                        print(e)
    print("Complete")
    print("Information obtained:\n{}".format(result))
    complete = SubmitQuery(result)
    return result

def GetTime():
    import datetime

    timestamp = datetime.datetime.today().replace(microsecond = 0)
    year = datetime.datetime.today().strftime("%Y")
    month = datetime.datetime.today().strftime("%m")
    day = datetime.datetime.today().strftime("%d")

    return (timestamp, year, month, day)

def GetFlag():
    '''
        Get option used to run command.
        Returns:Flag if there is an option specified,
                False if none,
    '''
    flag_selected = ''

    try:
        flag_selected = str(sys.argv[-2:-1][0])
    except:
        print("\nInput a valid option. Run with '-h' flag for help")
        sys.exit()

    #Handles certain exceptions when making command
    if len(flag_selected) != 1:
        flag_selected = str(sys.argv[-1:][0])
        if flag_selected != '-h':
            flag_selected = str(sys.argv[-2:-1][0])
            if flag_selected != "-h" and flag_selected != "-f" and flag_selected != "-n":
                flag_selected = str(sys.argv[-1:][0])

    if flag_selected != '':
        return flag_selected
    else: return False;

def HelpDialogue():
    if flag == '-h':
        HelpDialog = '''
            Usage: python F5StatoDB.py [OPTION] [arg] [OPTIONAL]

            Options and arguments:
                -h\t:\tDisplays help
                -f\t:\tSpecify file to get device IP Addresses\t[-f] <FILENAME>
                -n\t:\tSpecify individual IP Address \t[-n] <IP ADDRESS>
                \t\t- Append: '| column -t' for output formatting

            OPTIONAL:
                -o <FILENAME>\t:\tExport info to specified filepath
        '''
        print(HelpDialog)

def SubmitQuery(res):
    # Submits results to database
    import MySQLdb

    #Open file to get credentials
    db_host, db_user, db_pass='','',''

    with open('/path/to/pythonmysql.ini') as f:
        db_host = f.readline().strip('\n')
        db_user = f.readline().strip('\n')
        db_pass = f.readline().strip('\n')
        db_socket = f.readline().strip('\n')

    #Establish DB Connection
    try:
        print("Attempting to connect to db...", end = "")
        conn = MySQLdb.connect(db_host, db_user, db_pass, db = "NMG", unix_socket = db_socket)
        cursor = conn.cursor()
    except Exception as e:
        print("FAILED")
        print('Unable to connect to the database:\n{}'.format(e));
        sys.exit()

    try:
        print("Deleting records older than 5 days old... ", end="")
        delete_query = "DELETE FROM F5_Stat WHERE DATE(Timestamp) < DATE_SUB(NOW(), INTERVAL 5 DAY)"
        cursor.execute(delete_query)
        conn.commit()
        print("Complete")
    except Exception as e:
        print("ERROR! : \n{}".format(e))

    print("Executing queries...",end="")
    for info in res['data']:
        print("No members found: HOSTNAME:{},  VIPNAME: {}".format(info['Hostname'],info['VIP_Name']))
        if not 'Members' in info:
            info['Members'] = [{
                          "MemberName"    : "None",
                          "MemberIP"      : "None",
                          "MemberPort"    : "None",
                          "MemberRD"      : "None",
                          "MemberAState"  : "None",
                          "MemberEState"  : "None",
                          "MemberReason"  : "None",
                        }]
        for member in info["Members"]:
            info['VIPReason'] = conn.escape_string(info['VIPReason']).decode()
            insert_query = "INSERT INTO F5_Stat (Timestamp,Hostname,PoolName,MemberName,MemberIP,MemberPort,Member_RD,MemberAvailState,MemberEnabledState,MemberStatReason,VIP_Name,VIP_IP,VIP_Port,VIP_RD,VIP_Avail_State,VIP_En_State, VIP_Reason) VALUES('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(timestamp,info["Hostname"],info["Default_Pool"],member["MemberName"],member["MemberIP"],member["MemberPort"],member['MemberRD'],member["MemberAState"],member["MemberEState"],member["MemberReason"],info["VIP_Name"],info["VIP_IP"],info["VIP_Port"],info['VIP_RD'],info["VIP_AState"],info["VIP_EState"],info['VIPReason'])
            try:
                cursor.execute(insert_query)
            except Exception as e:
                print("Failed \n\t{}".format(e))
                return False
    try:
        print("Committing... ", end = "")
        conn.commit()
        print("Success\n\n")
    except Exception as e:
        print("Failed \n\t{}".format(e))

    print("=================================")
    # Write to the CSV file
    # WriteToCSV(res)
    return True

def PrintInfo(res):
    # Prints out the information
    from terminaltables import AsciiTable

    # Write the headers for now
    table_data = [
        ['Index','DefaultPool','MemberName','MemberIP','MemberPort','MemberRD','MemberAState','MemberEState']
    ]


    for index, i in enumerate(res["data"]):
        if "Members" not in i:
            table_data.append([ index, i['Default_Pool'], "None", "None", "None", "None", "None"])
        else:
            for member in i['Members']:
                table_data.append( [index,
                                    i['Default_Pool'],
                                    member["MemberName"],
                                    member["MemberIP"],
                                    member["MemberPort"],
                                    member['MemberRD'],
                                    member["MemberAState"],
                                    member["MemberEState"],
                                    member["MemberReason"].strip()]
                                ])

    table = AsciiTable(table_data)
    print(table.table)

    return True

def get_fileinfo(filename):
    '''
        Check if the filename is a valid file path. else print error and quit
    '''
    ip_add, hostname = "", "";
    fileinfo = []

    if os.path.isfile(filename):
        pass;
    else:
        print("ERROR: File does not exist\n\t {}".format(filename))

    try:
        # Try to open the file, raise error if unable to
        with open(filename) as f:
            for content in f:
                try:
                    # Try to parse through data, raise error if not in correct format
                    ip_add, hostname = content.split(',', 1)
                    ip_add = ip_add.strip()
                    hostname = hostname.strip()

                    fileinfo.append([ip_add, hostname])
                except Exception:
                    print("Data in file is in incorrect format.")
    except Exception as e:
        error = "Unable to open file: {}".format(filename)
        print(error)
        print(e)

    return fileinfo;


if __name__ == "__main__":
    '''
        This should always be the case
    '''
    # Init Vars
    complete = False;

    #Get current timestamp, year, month, day
    timestamp, year, month, day = GetTime()

    # Command Handler
    flag = GetFlag()

    if flag:
        complete_res = {}
        if not 'data' in complete_res:
            complete_res['data'] = []

        if flag == '-h':
            print("[HELP MODE]")
            HelpDialogue();
            complete = True;

        if flag == '-f':
            print("[FILE MODE]")

            processes = []

            # GET the filename from the prompt
            try:
                filename = str(sys.argv[2:3][0])
            except Exception as e:
                print("Please specify a filename. Filename cannot be blank")
                sys.exit()

            file_info = get_fileinfo(filename)
            with Manager() as manager:
                L = manager.list()

                for ip_add, hostname in file_info:
                    L.append([ip_add, hostname])
                for i in range(len(L)):
                    p = Process(target=GetDeviceInfo, args=(L[i][0],L[i][1],))
                    p.start()
                    processes.append(p)

                for p in processes:
                    p.join()

            print("Runtime: {}".format(datetime.now() - start))

        elif flag == '-n':
            print("[INDIVIDUAL IP MODE]")
            try:
                ip_addr = str(sys.argv[2:3][0])
            except Exception:
                print("Device not found! Check the IP address entered: {}".format(ip_addr))
                sys.exit()
            result = GetDeviceInfo(ip_addr)
            print(result)

            complete = PrintInfo(result)


    if complete:
        print("[DONE]")
