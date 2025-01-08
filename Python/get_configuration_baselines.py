#
# _author_ = Trevor Squillario <Trevor_Squillario@Dell.com
#
# Copyright (c) 2024 Dell EMC Corporation
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
Gets a list of all configuration baselines available from an OME server or baselines associated
with a specific device.

#### Description
This script uses the OME REST API to find baselines associated
with a given server. For authentication X-Auth is used over Basic
Authentication. Note: The credentials entered are not stored to disk.

#### Python Example
`python get_configuration_baselines.py --ip ome.example.com --user admin --password "calvin" --get-baselines`
`python get_configuration_baselines.py --ip ome.example.com --user admin --password "calvin" --get-baseline-report --baseline "Gold_config" --export /tmp/summary.csv --filter "Compliant"`
`python get_configuration_baselines.py --ip ome.example.com --user admin --password "calvin" --get-baseline-detail-report --baseline "Gold_config" --export /tmp/detail.csv`
`python get_configuration_baselines.py --ip ome.example.com --user admin --password "calvin" --get-baseline-detail-report --baseline "Gold_config" --export /tmp/detail.csv --filter "Compliant"`
"""

import argparse
import json
import sys, os
import csv
from argparse import RawTextHelpFormatter
from getpass import getpass
from pprint import pprint
from urllib.parse import urlparse
import http
import logging
import requests
import urllib3

http.client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

compliance_status = {
    1: "Compliant",
    2: "Noncompliant",
    3: "Attribute Missing"
}

def authenticate(ome_ip_address: str, ome_username: str, ome_password: str) -> dict:
    """
    Authenticates with OME and creates a session

    Args:
        ome_ip_address: IP address of the OME server
        ome_username:  Username for OME
        ome_password: OME password

    Returns: A dictionary of HTTP headers

    Raises:
        Exception: A generic exception in the event of a failure to connect.
    """

    authenticated_headers = {'content-type': 'application/json'}
    session_url = 'https://%s/api/SessionService/Sessions' % ome_ip_address
    user_details = {'UserName': ome_username,
                    'Password': ome_password,
                    'SessionType': 'API'}
    try:
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=authenticated_headers)
    except requests.exceptions.ConnectionError:
        print("Failed to connect to OME. This typically indicates a network connectivity problem. Can you ping OME?")
        sys.exit(0)

    if session_info.status_code == 201:
        authenticated_headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        return authenticated_headers
    else:
        print("There was a problem authenticating with OME. Are you sure you have the right username, password, "
              "and IP?")
        raise Exception("There was a problem authenticating with OME. Are you sure you have the right username, "
                        "password, and IP?")


def get_data(authenticated_headers: dict, url: str, odata_filter: str = None, max_pages: int = None) -> dict:
    """
    This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
    handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
    pages to get a complete listing.

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        url: The API url against which you would like to make a request
        odata_filter: An optional parameter for providing an odata filter to run against the API endpoint.
        max_pages: The maximum number of pages you would like to return

    Returns: Returns a dictionary of data received from OME

    """

    next_link_url = None

    if odata_filter:
        count_data = requests.get(url + '?$filter=' + odata_filter, headers=authenticated_headers, verify=False)

        if count_data.status_code == 400:
            print("Received an error while retrieving data from %s:" % url + '?$filter=' + odata_filter)
            pprint(count_data.json()['error'])
            return {}

        count_data = count_data.json()
        if count_data['@odata.count'] <= 0:
            print("No results found!")
            return {}
    else:
        count_data = requests.get(url, headers=authenticated_headers, verify=False).json()

    if 'value' in count_data:
        data = count_data['value']
    else:
        data = count_data

    if '@odata.nextLink' in count_data:
        # Grab the base URI
        next_link_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url)) + count_data['@odata.nextLink']

    i = 1
    while next_link_url is not None:
        # Break if we have reached the maximum number of pages to be returned
        if max_pages:
            if i >= max_pages:
                break
            else:
                i = i + 1
        response = requests.get(next_link_url, headers=authenticated_headers, verify=False)
        next_link_url = None
        if response.status_code == 200:
            requested_data = response.json()
            if requested_data['@odata.count'] <= 0:
                print("No results found!")
                return {}

            # The @odata.nextLink key is only present in data if there are additional pages. We check for it and if it
            # is present we get a link to the page with the next set of results.
            if '@odata.nextLink' in requested_data:
                next_link_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url)) + \
                                requested_data['@odata.nextLink']

            if 'value' in requested_data:
                data += requested_data['value']
            else:
                data += requested_data
        else:
            print("Unknown error occurred. Received HTTP response code: " + str(response.status_code) +
                  " with error: " + response.text)
            raise Exception("Unknown error occurred. Received HTTP response code: " + str(response.status_code)
                            + " with error: " + response.text)

    return data

def get_configuration_baselines(authenticated_headers: dict,
                           ome_ip_address: str,
                           name: str = None
                           ):
    """
    Gets a list of configuration baselines from OME

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        name: Baseline Name
    """

    configuration_baselines = \
        get_data(authenticated_headers, "https://%s/api/TemplateService/Baselines" % ome_ip_address)  # type: dict

    if not configuration_baselines:
        print("Unable to retrieve configuration list from %s. This could happen for many reasons but the most likely is a"
              " failure in the connection." % ome_ip_address)
        exit(0)

    if len(configuration_baselines) <= 0:
        print("No configuration baselines found on this OME server: " + ome_ip_address + ". Exiting.")
        exit(0)

    configuration_baseline_list = []  # type: list
    if name:
        for configuration_baseline in configuration_baselines:
            if configuration_baseline["Name"] == name:
                configuration_baseline_list.append(configuration_baseline)
    else:
        for configuration_baseline in configuration_baselines:
            configuration_baseline_list.append(configuration_baseline)

    return configuration_baseline_list

def get_configuration_baseline_report(authenticated_headers: dict,
                           ome_ip_address: str,
                           filter: int,
                           baseline_id: str = None
                           ):
    """
    Gets a configuration baseline summary report from OME

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        baseline_id: Id of Baseline
    """

    configuration_baselines = \
        get_data(authenticated_headers, "https://%s/api/TemplateService/Baselines(%s)/DeviceConfigComplianceReports" % (ome_ip_address, baseline_id))  # type: dict

    if not configuration_baselines:
        print("Unable to retrieve configuration list from %s. This could happen for many reasons but the most likely is a"
              " failure in the connection." % ome_ip_address)
        exit(0)

    if len(configuration_baselines) <= 0:
        print("No configuration baselines found on this OME server: " + ome_ip_address + ". Exiting.")
        exit(0)

    configuration_baseline_list = []  # type: list
    for configuration_baseline in configuration_baselines:
        summary_row = {}
        summary_row["Compliance"] = compliance_status[configuration_baseline["ComplianceStatus"]]
        summary_row["DeviceName"] = configuration_baseline["DeviceName"]
        summary_row["IPAddress"] = configuration_baseline["IpAddress"]
        summary_row["Type"] = configuration_baseline["DeviceType"]
        summary_row["Model"] = configuration_baseline["Model"]
        summary_row["ServiceTag"] = configuration_baseline["ServiceTag"]
        summary_row["LastSuccessfulInventoryTime"] = configuration_baseline["InventoryTime"]
        if filter:
            if configuration_baseline["ComplianceStatus"] == filter:
                configuration_baseline_list.append(summary_row)
        else: 
            configuration_baseline_list.append(summary_row)

    return configuration_baseline_list

def process_subattributes(device_name: str, component: str, path: str, subattribute: any, filter: int):
    detail_list = []
    detail_row = {}
    if len(subattribute["Attributes"]) > 0:
        for attribute in subattribute["Attributes"]:
            detail_row["DeviceName"] = device_name
            detail_row["Component"] = component
            detail_row["Path"] = path
            detail_row["Attribute"] = attribute["DisplayName"]
            detail_row["Status"] = compliance_status[attribute["ComplianceStatus"]]
            detail_row["Expected"] = attribute["ExpectedValue"]
            detail_row["Current"] = attribute["Value"]
            if filter:
                if attribute["ComplianceStatus"] == filter:
                    detail_list.append(detail_row)
            else: 
                detail_list.append(detail_row)
            detail_row = {}

    else:
        for subattribute2 in subattribute["ComplianceSubAttributeGroups"]:
            path = subattribute2["DisplayName"]
            detail_list.extend(process_subattributes(device_name=device_name, component=component, path=path, subattribute=subattribute2, filter=filter))

    return detail_list

def get_configuration_baseline_detail_report(authenticated_headers: dict,
                           ome_ip_address: str,
                           filter: int,
                           baseline_id: str = None
                           ):
    """
    Gets a configuration baseline detail report from OME

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        baseline_id: Id of Baseline
    """

    configuration_baselines = \
        get_data(authenticated_headers, "https://%s/api/TemplateService/Baselines(%s)/DeviceConfigComplianceReports" % (ome_ip_address, baseline_id)) 

    if not configuration_baselines:
        print("Unable to retrieve configuration list from %s. This could happen for many reasons but the most likely is a"
              " failure in the connection." % ome_ip_address)
        exit(0)

    if len(configuration_baselines) <= 0:
        print("No configuration baselines found on this OME server: " + ome_ip_address + ". Exiting.")
        exit(0)

    configuration_baseline_detail_list = []  # type: list
    for configuration_baseline in configuration_baselines:
        device_name = configuration_baseline["DeviceName"]
        configuration_baseline_device_id = configuration_baseline["Id"]
        url = "https://%s/api/TemplateService/Baselines(%s)/DeviceConfigComplianceReports(%s)/DeviceComplianceDetails" % (ome_ip_address, baseline_id, configuration_baseline_device_id)
        report_entry_detail = get_data(authenticated_headers, url)  
        for attributegroup in report_entry_detail["ComplianceAttributeGroups"]:
            component = attributegroup["DisplayName"]
            for subattribute in attributegroup["ComplianceSubAttributeGroups"]:
                path = subattribute["DisplayName"]
                detail_list = process_subattributes(device_name=device_name, component=component, path=path, subattribute=subattribute, filter=filter)
                configuration_baseline_detail_list.extend(detail_list)

    return configuration_baseline_detail_list

def export_csv(data: list, file_name: str):
    if len(data) > 0:
        keys = data[0].keys()

        with open(file_name, 'w', newline='') as output_file:
            dict_writer = csv.DictWriter(output_file, keys)
            dict_writer.writeheader()
            dict_writer.writerows(data)

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for the OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for the OME Appliance")
    parser.add_argument("--get-baselines", "-l", required=False, action='store_true',
                        help="Get list of Configuration Baselines")
    parser.add_argument("--baseline", "-b", required=False,
                        help="Configuration Baseline name")
    parser.add_argument("--get-baseline-report", "-r", required=False, action='store_true',
                        help="Get report for Configuration Baseline")
    parser.add_argument("--get-baseline-detail-report", "-d", required=False, action='store_true',
                        help="Get detail report for Configuration Baseline")
    parser.add_argument("--filter", "-f", required=False,
                        help="Filter by compliance status", choices=compliance_status.values())
    parser.add_argument("--export", "-e", required=False,
                        help="Specify full path to export to CSV")
    args = parser.parse_args()

    if not args.password:
        if not sys.stdin.isatty():
            # notify user that they have a bad terminal
            # perhaps if os.name == 'nt': , prompt them to use winpty?
            print("Your terminal is not compatible with Python's getpass module. You will need to provide the"
                  " --password argument instead. See https://stackoverflow.com/a/58277159/4427375")
            sys.exit(0)
        else:
            password = getpass()
    else:
        password = args.password

    if args.get_baseline_report or args.get_baseline_detail_report:
        if not args.baseline:
            parser.error("--baseline must be specified")

    headers = authenticate(args.ip, args.user, password)

    if not headers:
        exit(0)

    filter = None
    if args.filter:
        for id, name in compliance_status.items():
            if name == args.filter:
                filter = id

    if args.get_baselines:
        configuration_baselines = get_configuration_baselines(headers, args.ip, args.baseline)
        if len(configuration_baselines) > 0:
            for baseline in configuration_baselines:
                print(baseline["Name"])
        else:
            print("No configuration baselines found!")

    if args.get_baseline_report:
        configuration_baselines = get_configuration_baselines(headers, args.ip, args.baseline)
        if len(configuration_baselines) > 0:
            baseline_id = configuration_baselines[0]["Id"]
            configuration_baseline_report = get_configuration_baseline_report(authenticated_headers=headers, ome_ip_address=args.ip, baseline_id=baseline_id, filter=filter)
            if args.export:
                export_csv(configuration_baseline_report, args.export)
            else:
                print(configuration_baseline_report)
        else:
            print("No configuration baselines found!")

    if args.get_baseline_detail_report:
        configuration_baselines = get_configuration_baselines(headers, args.ip, args.baseline)
        if len(configuration_baselines) > 0:
            baseline_id = configuration_baselines[0]["Id"]
            configuration_baseline_report = get_configuration_baseline_detail_report(authenticated_headers=headers, ome_ip_address=args.ip, baseline_id=baseline_id, filter=filter)
            if args.export:
                export_csv(configuration_baseline_report, args.export)
            else:
                print(configuration_baseline_report)
        else:
            print("No configuration baselines found!")