#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
#
# Copyright (c) 2021 Dell EMC Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
#### Synopsis
Script to get the list of virtual addresses in an Identity Pool

#### Description
Will export to a CSV file called IdentityPoolUsage.csv in the current directory.

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
```
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd>
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd> --id 11
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd> --id 11 --outfile "/tmp/temp.csv"
```
"""

import argparse
import csv
import json
import os
from argparse import RawTextHelpFormatter
from getpass import getpass

import requests
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session_auth_token = {}


def get_session(ip_address, user_name, password):
    session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
    headers = {'content-type': 'application/json'}
    user_details = {'UserName': user_name,
                    'Password': password,
                    'SessionType': 'API'}
    session_info = requests.post(session_url, verify=False,
                                 data=json.dumps(user_details),
                                 headers=headers)
    if session_info.status_code == 201:
        session_info_token = session_info.headers['X-Auth-Token']
        session_info_data = session_info.json()
        session_auth_token = {
            "token": session_info_token,
            "id": session_info_data['Id']
        }
    return session_auth_token


def delete_session(ip_address, headers, id):
    session_url = "https://%s/api/SessionService/Sessions('%s')" % (ip_address, id)
    session_info = requests.delete(session_url, verify=False, headers=headers)
    if session_info.status_code == 204:
        return True
    else: 
        print ("Unable to delete session %s" % id)
        return False

def get_identitypool_usage(base_uri, headers, user_name, password, identitypool_id, outfile):
    next_link_url = None
    # Display Identity Pools
    identitypool_url = base_uri + '/api/IdentityPoolService/IdentityPools'
    identitypool_response = requests.get(identitypool_url, headers=headers, verify=False)
    if identitypool_response.status_code == 200:
        identitypool_data = identitypool_response.json()
        identitypool_data = identitypool_data['value']
        for i in identitypool_data:
            print("Id: %s, Name: %s" %(i["Id"], i["Name"]))
    else:
        print("Unable to retrieve device list from %s" % (ip_address))

    if identitypool_id == None:
        identitypool_id_prompt = input("Please Enter Identity Pool Id: ")
        identitypool_id = identitypool_id_prompt

    # Get Identity Pool Usage Sets
    identitypool_usageset_url = base_uri + "/api/IdentityPoolService/IdentityPools(%s)/UsageIdentitySets" % (identitypool_id)
    identitypool_usageset_response = requests.get(identitypool_usageset_url, headers=headers, verify=False)
    if identitypool_usageset_response.status_code == 200:
        identitypool_usageset_data = identitypool_usageset_response.json()
        identitypool_usageset_data = identitypool_usageset_data['value']
        
        detailentries = []
        for usageset in identitypool_usageset_data:
            usageset_id = usageset["IdentitySetId"]
            usageset_name = usageset["Name"]

            identitypool_usageset_detail_url = base_uri + "/api/IdentityPoolService/IdentityPools(%s)/UsageIdentitySets(%s)/Details" % (identitypool_id, usageset_id)
            identitypool_usageset_detail_response = requests.get(identitypool_usageset_detail_url, headers=headers, verify=False)
            if identitypool_usageset_detail_response.status_code == 200:
                identitypool_usageset_detail_json = identitypool_usageset_detail_response.json()
                identitypool_usageset_detail_data = identitypool_usageset_detail_json['value']
                for detailentry in identitypool_usageset_detail_data:
                    entry = {
                        "IdentityType": usageset_name,
                        "ChassisName": detailentry["DeviceInfo"]["ChassisName"],
                        "ServerName": detailentry["DeviceInfo"]["ServerName"],
                        "ManagementIp": detailentry["DeviceInfo"]["ManagementIp"],
                        "NicIdentifier": detailentry["NicIdentifier"],
                        "MacAddress": detailentry["MacAddress"]
                    }
                    detailentries.append(entry)
                
                if '@odata.nextLink' in identitypool_usageset_detail_json:
                    next_link_url = base_uri + identitypool_usageset_detail_json['@odata.nextLink']
                    while next_link_url:
                        next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                        if next_link_response.status_code == 200:
                            next_link_json = next_link_response.json()
                            next_link_json_data += next_link_json['value']
                            for detailentry in next_link_json_data:
                                entry = {
                                    "IdentityType": usageset_name,
                                    "ChassisName": detailentry["DeviceInfo"]["ChassisName"],
                                    "ServerName": detailentry["DeviceInfo"]["ServerName"],
                                    "ManagementIp": detailentry["DeviceInfo"]["ManagementIp"],
                                    "NicIdentifier": detailentry["NicIdentifier"],
                                    "MacAddress": detailentry["MacAddress"]
                                }
                                detailentries.append(entry)
                            
                            if '@odata.nextLink' in next_link_json:
                                next_link_url = base_uri + next_link_json['@odata.nextLink']
                            else:
                                next_link_url = None
                        else:
                            next_link_url = None
                            print("Unable to retrieve items from nextLink %s" % (next_link_url))
        
        # Export results to CSV
        if (len(detailentries) > 0):
            currentDirectory = os.path.dirname(os.path.abspath(__file__))
            if outfile == None:
                outFilePath = currentDirectory + os.path.sep + "IdentityPoolUsage.csv"                        
            else:
                outFilePath = outfile                        
            outputFile = open(outFilePath, 'w') 
            output = csv.writer(outputFile) 
            output.writerow(detailentries[0].keys()) 
            for row in detailentries:
                output.writerow(row.values())
            print("Exported data to %s" %(outFilePath))
            outputFile.close()
        else:
            print("No usage data found")
    else:
        print("Unable to retrieve list from %s" % (ip_address))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--id", required=False,
                        help="Identity Pool Id")
    parser.add_argument("--out-file", "-o", required=False,
                        help="Full path to CSV file")

    ARGS = parser.parse_args()
    base_uri = 'https://%s' %(ARGS.ip)
    auth_token = get_session(ARGS.ip, ARGS.user, ARGS.password)
    headers = {'content-type': 'application/json'}
    if auth_token.get('token') != None:
        headers['X-Auth-Token'] = auth_token['token']
    else:
        print("Unable to create a session with appliance %s" % (base_uri))
        quit()

    try: 
        if ARGS.out_file:
            get_identitypool_usage(base_uri, headers, ARGS.user, ARGS.password, ARGS.id, ARGS.out_file)
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])
