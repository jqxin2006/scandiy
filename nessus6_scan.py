import requests
import json
import time
import sys
import queue
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring
import ConfigParser

config = ConfigParser.ConfigParser()
config.read("general.config")

url = config.get("nessus", "endpoint")
verify = False
token = ''
username = config.get("nessus", "username")
password = config.get("nessus", "password")




def build_url(resource):
    return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None, params=None):
    """
    Send a request

    Send a request to Nessus based on the specified data. If the session token
    is available add it to the request. Specify the content type as JSON and
    convert the data to JSON format.
    """
    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}

    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=params, headers=headers, verify=verify)

    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print e['error']
        sys.exit()

    # When downloading a scan we need the raw contents not the JSON data. 
    if 'download' in resource:
        return r.content

    # All other responses should be JSON data. Return raw content if they are
    # not.
    try:
        return r.json()
    except ValueError:
        return r.content


def login(usr, pwd):
    """
    Login to nessus.
    """

    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', data=login)

    return data['token']


def logout():
    """
    Logout of nessus.
    """

    connect('DELETE', '/session')


def get_policies():
    """
    Get scan policies

    Get all of the scan policies but return only the title and the uuid of
    each policy.
    """

    data = connect('GET', '/editor/policy/templates')

    return dict((p['title'], p['uuid']) for p in data['templates'])


def get_history_ids(sid):
    """
    Get history ids

    Create a dictionary of scan uuids and history ids so we can lookup the
    history id by uuid.
    """
    data = connect('GET', '/scans/{0}'.format(sid))

    return dict((h['uuid'], h['history_id']) for h in data['history'])


def get_scan_history(sid, hid):
    """
    Scan history details

    Get the details of a particular run of a scan.
    """
    params = {'history_id': hid}
    data = connect('GET', '/scans/{0}'.format(sid), params)

    return data['info']


def add(name, desc, targets, pid):
    """
    Add a new scan

    Create a new scan using the policy_id, name, description and targets. The
    scan will be created in the default folder for the user. Return the id of
    the newly created scan.
    """

    scan = {'uuid': pid,
            'settings': {
                'name': name,
                'description': desc,
                'text_targets': targets}
            }

    data = connect('POST', '/scans', data=scan)

    return data['scan']


def update(scan_id, name, desc, targets, pid=None):
    """
    Update a scan

    Update the name, description, targets, or policy of the specified scan. If
    the name and description are not set, then the policy name and description
    will be set to None after the update. In addition the targets value must
    be set or you will get an "Invalid 'targets' field" error.
    """

    scan = {}
    scan['settings'] = {}
    scan['settings']['name'] = name
    scan['settings']['desc'] = desc
    scan['settings']['text_targets'] = targets

    if pid is not None:
        scan['uuid'] = pid

    data = connect('PUT', '/scans/{0}'.format(scan_id), data=scan)

    return data


def launch(sid):
    """
    Launch a scan

    Launch the scan specified by the sid.
    """

    data = connect('POST', '/scans/{0}/launch'.format(sid))

    return data['scan_uuid']


def status(sid, hid):
    """
    Check the status of a scan run

    Get the historical information for the particular scan and hid. Return
    the status if available. If not return unknown.
    """ 

    d = get_scan_history(sid, hid)
    return d['status']


def export_status(sid, fid):
    """
    Check export status

    Check to see if the export is ready for download.
    """

    data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))

    return data['status'] == 'ready'


def export(sid, hid):
    """
    Make an export request

    Request an export of the scan results for the specified scan and
    historical run. In this case the format is hard coded as nessus but the
    format can be any one of nessus, html, pdf, csv, or db. Once the request
    is made, we have to wait for the export to be ready.
    """

    data = {'history_id': hid,
            'format': 'nessus',
            'chapters': 'vuln_hosts_summary'}

    data = connect('POST', '/scans/{0}/export'.format(sid), data=data)

    fid = data['file']

    while export_status(sid, fid) is False:
        time.sleep(5)

    return fid


def download(sid, fid):
    """
    Download the scan results

    Download the scan results stored in the export file specified by fid for
    the scan specified by sid.
    """

    data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
    filename = 'nessus_{0}_{1}.nessus'.format(sid, fid)

    print('Saving scan results to {0}.'.format(filename))
    with open(filename, 'w') as f:
        f.write(data)


def delete(sid):
    """
    Delete a scan

    This deletes a scan and all of its associated history. The scan is not
    moved to the trash folder, it is deleted.
    """

    connect('DELETE', '/scans/{0}'.format(scan_id))


def history_delete(sid, hid):
    """
    Delete a historical scan.

    This deletes a particular run of the scan and not the scan itself. the
    scan run is defined by the history id.
    """

    connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))


def get_all_messages():
    client_id = config.get("nessus", "client_id")
    the_scan = queue.ScanQueue()
    the_messages = the_scan.get_queue_message(client_id = client_id)
    print the_messages

def claim_a_message():
    client_id = config.get("nessus", "client_id")
    the_scan = queue.ScanQueue()
    json_msg = the_scan.claim_a_message(client_id = client_id)
    if len(json_msg) > 0:
        print json_msg
        scan_id = json_msg[0]["body"]["scan_id"]
        href = json_msg[0]["href"]
        print scan_id
        print href
            

    return json_msg

def get_vulnerability(file_name):
    tree = ET.parse(file_name)
    root = tree.getroot()
    issues = []

    preferences = root.findall("Policy/Preferences/ServerPreferences/preference")
    for preference in preferences:
        print preference
        result = {}
        for node in preference:
            result[node.tag] = node.text
        if result["name"] == "plugin_set":
            plugin_set = result["value"]
    print plugin_set
    print len(plugin_set.split(";"))

    testsuites = Element("testsuites")
    for elem in root.findall("Report/ReportHost"):
        testsuite = SubElement(testsuites, "testsuite")
        for issue in elem.findall("ReportItem"):
            testcase = SubElement(testsuite, "testcase")
            attribs = issue.attrib
            failure = SubElement(testcase, "failure")
            for atom in issue:
                if atom.tag == "description":
                    failure.text = atom.text 

            testcase_attribs = {}
            testcase_attribs["name"] = attribs["pluginName"]
            testcase_attribs["classname"] = attribs["pluginID"]
            testcase.attrib = testcase_attribs
            print attribs
            issues.append(issue)
    print issues
    print tostring(testsuites)



if __name__ == '__main__':
    the_result = claim_a_message()
    if (len(the_result) > 0):
        our_scan_id = the_result[0]
        message = the_result[1]
        claim_id = the_result[2]

    print the_result    
    #get_vulnerability("nessus_1024_510511181.nessus")

    sys.exit(-1)

    ips=["127.0.0.1"]
    print ips

    
    print('Login')
    token = login(username, password)

    print('Adding new scan.')
    policies = get_policies()
    print policies


    policy_id = policies['Internal PCI Network Scan']
    scan_data = add('Test Scan', 'Create a new scan with API', '127.0.0.1', policy_id)
    scan_id = scan_data['id']

    #print('Updating scan with new targets.')
    #update(scan_id, scan_data['name'], scan_data['description'], '10.230.228.0/24')

    print('Launching new scan.')
    scan_uuid = launch(scan_id)
    history_ids = get_history_ids(scan_id)
    history_id = history_ids[scan_uuid]
    while status(scan_id, history_id) != 'completed':
        time.sleep(5)

    print('Exporting the completed scan.')
    file_id = export(scan_id, history_id)
    download(scan_id, file_id)

    filename = 'nessus_{0}_{1}.nessus'.format(sid, fid)
    print filename
    print('Deleting the scan.')
    #history_delete(scan_id, history_id)
    #delete(scan_id)

    print('Logout')
    logout()
