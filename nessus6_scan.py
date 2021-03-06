import requests
import json
import time
import sys
import queue
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring
import ConfigParser
import datetime
from time import gmtime, strftime
import base64
import zlib
import threading
from retrying import retry
import logging
import logging.handlers

config = ConfigParser.ConfigParser()
config.read("general.config")
# set up Nessus scanning box
url = config.get("nessus", "endpoint")
verify = False
token = ''
username = config.get("nessus", "username")
password = config.get("nessus", "password")

LOG_FILENAME = './logs/scanner.log'
# Set up a specific logger with our desired output level
my_logger = logging.getLogger('nessus_agent')
my_logger.setLevel(logging.DEBUG)
# Add the log message handler to the logger
handler = logging.handlers.RotatingFileHandler(LOG_FILENAME,
                                               maxBytes=2000000,
                                               backupCount=10,
                                               )

formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

my_logger.addHandler(handler)


def build_url(resource):
    return '{0}{1}'.format(url, resource)


@retry(stop_max_attempt_number=7, wait_fixed=5000)
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
        r = requests.post(build_url(resource), data=data,
                          headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data,
                         headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data,
                            headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=params,
                         headers=headers, verify=verify)

    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        my_logger.error(e['error'])
        # sys.exit()

    # When downloading a scan we need the raw contents not the JSON data.
    if 'download' in resource:
        return r.content

    # All other responses should be JSON data. Return raw content if they are
    # not.
    try:
        return r.json()
    except ValueError:
        return r.content


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def login(usr, pwd):
    """
    Login to nessus.
    """

    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', data=login)

    return data['token']


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def logout():
    """
    Logout of nessus.
    """

    connect('DELETE', '/session')


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def get_policies():
    """
    Get scan policies

    Get all of the scan policies but return only the title and the uuid of
    each policy.
    """

    data = connect('GET', '/editor/policy/templates')

    return dict((p['title'], p['uuid']) for p in data['templates'])


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def get_history_ids(sid):
    """
    Get history ids

    Create a dictionary of scan uuids and history ids so we can lookup the
    history id by uuid.
    """
    data = connect('GET', '/scans/{0}'.format(sid))

    return dict((h['uuid'], h['history_id']) for h in data['history'])


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def get_scan_history(sid, hid):
    """
    Scan history details

    Get the details of a particular run of a scan.
    """
    params = {'history_id': hid}
    data = connect('GET', '/scans/{0}'.format(sid), params)

    return data['info']


@retry(stop_max_attempt_number=7, wait_fixed=5000)
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


@retry(stop_max_attempt_number=7, wait_fixed=5000)
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


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def launch(sid):
    """
    Launch a scan

    Launch the scan specified by the sid.
    """

    data = connect('POST', '/scans/{0}/launch'.format(sid))

    return data['scan_uuid']


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def status(sid, hid):
    """
    Check the status of a scan run

    Get the historical information for the particular scan and hid. Return
    the status if available. If not return unknown.
    """

    d = get_scan_history(sid, hid)
    my_logger.info(d)
    return d['status']


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def export_status(sid, fid):
    """
    Check export status

    Check to see if the export is ready for download.
    """

    data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))

    return data['status'] == 'ready'


@retry(stop_max_attempt_number=7, wait_fixed=5000)
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


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def download(sid, fid):
    """
    Download the scan results

    Download the scan results stored in the export file specified by fid for
    the scan specified by sid.
    """

    data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
    filename = 'nessus_{0}_{1}.nessus'.format(sid, fid)

    my_logger.info('Saving scan results to {0}.'.format(filename))
    with open(filename, 'w') as f:
        f.write(data)


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def delete(sid):
    """
    Delete a scan

    This deletes a scan and all of its associated history. The scan is not
    moved to the trash folder, it is deleted.
    """

    connect('DELETE', '/scans/{0}'.format(scan_id))


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def history_delete(sid, hid):
    """
    Delete a historical scan.

    This deletes a particular run of the scan and not the scan itself. the
    scan run is defined by the history id.
    """

    connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def get_all_messages():
    client_id = config.get("nessus", "client_id")
    the_scan = queue.ScanQueue(my_logger=my_logger)
    the_messages = the_scan.get_queue_message(client_id=client_id)
    print the_messages


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def claim_a_message():
    client_id = config.get("nessus", "client_id")
    the_scan = queue.ScanQueue(my_logger=my_logger)
    json_msg = the_scan.claim_a_message(client_id=client_id)
    my_logger.info(" I am trying to claim a message!")
    my_logger.info(json_msg)
    if len(json_msg) > 0:
        scan_id = json_msg[0]["body"]["scan_id"]
        ips = json_msg[0]["body"]["targets"]
        origin_id = json_msg[0]["body"]["id"]
        href = json_msg[0]["href"]
        msg_id_claim_id = href.split("/")[-1]
        claim_id = msg_id_claim_id.split("?")[1]
        msg_id = msg_id_claim_id.split("?")[0]
        my_logger.debug("the msg_id_claim_id is:{}".format(msg_id_claim_id))
        # delete the message
        the_scan.delete_queue_message(client_id=client_id,
                                      message_id=msg_id_claim_id)
        my_logger.debug("delete the message with id of %s" % msg_id_claim_id)
        return (scan_id, origin_id, ips)
    else:
        return ()


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def get_vulnerability(filename="", run_time=10):
    tree = ET.parse(filename)
    root = tree.getroot()
    issues = []

    preferences = root.findall(
        "Policy/Preferences/ServerPreferences/preference")
    for preference in preferences:
        result = {}
        for node in preference:
            result[node.tag] = node.text
        if result["name"] == "plugin_set":
            plugin_set = result["value"]
    number_tests = len(plugin_set.split(";"))

    severity_match = {0: "S4", 1: "S3", 2: "S2", 3: "S1", 4: "S0"}
    testsuites = Element("testsuites")
    number_issues = 0
    for elem in root.findall("Report/ReportHost"):
        # need to get host name or IP address
        host = elem.attrib["name"]
        testsuite = SubElement(testsuites, "testsuite")
        for issue in elem.findall("ReportItem"):
            number_issues = number_issues + 1
            testcase = SubElement(testsuite, "testcase")
            attribs = issue.attrib
            failure = SubElement(testcase, "failure")
            description = ""
            synopsis = ""
            plugin_output = ""
            see_also = ""
            solution = ""
            fname = ""
            plugin_type = ""
            plugin_publication_date = ""
            plugin_modification_date = ""
            plugin_name = ""
            fname = ""
            script_version = ""
            risk_factor = ""

            for atom in issue:
                if atom.tag == "description":
                    description = atom.text
                elif atom.tag == "synopsis":
                    synopsis = atom.text
                elif atom.tag == "plugin_output":
                    plugin_output = atom.text
                elif atom.tag == "see_also":
                    see_also = atom.text
                elif atom.tag == "solution":
                    solution = atom.text
                elif atom.tag == "fname":
                    fname = atom.text
                elif atom.tag == "plugin_modification_date":
                    plugin_modification_date = atom.text
                elif atom.tag == "plugin_name":
                    plugin_name = atom.text
                elif atom.tag == "plugin_type":
                    plugin_type = atom.text
                elif atom.tag == "risk_factor":
                    risk_factor = atom.text
                elif atom.tag == "script_version":
                    script_version = atom.text

            testcase_attribs = {}
            sev_level = int(attribs["severity"])
            testcase_attribs["severity"] = severity_match[sev_level]
            testcase_attribs["name"] = attribs["pluginName"]
            testcase_attribs["pluginID"] = attribs["pluginID"]
            testcase_attribs["pluginName"] = attribs["pluginName"]
            testcase_attribs["classname"] = attribs["pluginID"]
            testcase.attrib = testcase_attribs
            failure.text = u"""Host:{}
                            Description:{}
                            Severity:{}
                            Fname:{}
                            Plugin_modification_date:{}
                            Plugin_name:{}
                            Plugin_publication_date:{}
                            Plugin_type:{}
                            Risk_factor:{}
                            Script_version:{}
                            See Also:{}
                            Solution:{}
                            Synopsis:{}
                            Plugin_output:{}
                            """.format(
                                host,
                                description,
                                testcase_attribs["severity"],
                                fname,
                                plugin_modification_date,
                                plugin_name,
                                plugin_publication_date,
                                plugin_type,
                                risk_factor,
                                script_version,
                                see_also,
                                solution,
                                synopsis,
                                plugin_output)
            issues.append(issue)
    testsuites_attribs = {}
    testsuites_attribs["failures"] = str(number_issues)
    testsuites_attribs["errors"] = "0"
    testsuites_attribs["name"] = "name"
    testsuites_attribs["skips"] = "0"
    testsuites_attribs["tests"] = str(number_tests)
    testsuites_attribs["host"] = host
    testsuites_attribs["time"] = str(run_time)
    testsuites.attrib = testsuites_attribs
    return tostring(testsuites)


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def update_queue_scan_started(scan_id="cb6399bb-3e8d-4d0f-8fd9-6bc22a969839"):
    config = ConfigParser.ConfigParser()
    config.read("general.config")
    client_id = config.get("nessus", "client_id")
    the_scan = queue.ScanQueue(my_logger=my_logger)
    thing = {"status": "scan started", "start_time": strftime(
                                "%Y-%m-%d %H:%M:%S", gmtime())}
    (status, href, start_time) = get_queue_scan_status(scan_id)
    my_logger.debug("updated scan id is {}".format(scan_id))
    if status == "not found":
        the_scan.post_queue_message(client_id=client_id,
                                    queue_name="ScanResponse",
                                    scan_id=scan_id,
                                    body=thing)


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def update_queue_scan_finished(scan_id="cb6399bb-3e8d-4d0f-8fd9-6bc22a969839",
                               scan_result="{}"):

    config = ConfigParser.ConfigParser()
    config.read("general.config")
    client_id = config.get("nessus", "client_id")
    the_scan = queue.ScanQueue(my_logger=my_logger)
    (status, href, start_time) = get_queue_scan_status(scan_id)
    thing = {"status": "scan finished",
             "finish_time": strftime("%Y-%m-%d %H:%M:%S", gmtime()),
             "start_time": start_time,
             "scan_result": scan_result}
    my_logger.debug("The scan_id is: {}".format(scan_id))
    if status == "scan started":
        message_id = href.split("/")[-1]
        my_logger.debug("message_id is: {}".format(message_id))
        the_scan.delete_queue_message(client_id=client_id,
                                      queue_name="ScanResponse",
                                      message_id=message_id)
        the_scan.post_queue_message(client_id=client_id,
                                    queue_name="ScanResponse",
                                    scan_id=scan_id,
                                    body=thing)


@retry(stop_max_attempt_number=7, wait_fixed=5000)
def get_queue_scan_status(scan_id="cb6399bb-3e8d-4d0f-8fd9-6bc22a969839"):
    config = ConfigParser.ConfigParser()
    config.read("general.config")
    client_id = config.get("nessus", "client_id")
    the_scan = queue.ScanQueue(my_logger=my_logger)
    the_messages = the_scan.get_queue_messages(queue_name="ScanResponse",
                                               client_id=client_id)
    status = "not found"
    href = "none"
    start_time = "none"

    if len(the_messages) > 0:
        the_messages_list = the_messages["messages"]
        for message in the_messages_list:
            if (message["body"]["scan_id"] == scan_id):
                status = message["body"]["status"]
                start_time = message["body"]["start_time"]
                href = message["href"]
    return (status, href, start_time)


def nessus_scan_ips(ips="127.0.0.1",
                    scan_name="test scan",
                    scan_id="cb6399bb-3e8d-4d0f-8fd9-6bc22a969839"):
    ''' Call Nessus scanner to scan given IPs and
        given scan name. It returns the scan result in
        JSON format
    '''

    start_time = time.time()
    my_logger.info('Nessus: Login')
    global token
    token = login(username, password)

    # update queue with statu of "scan started"
    my_logger.info("scan_id is: {} ".format(scan_id))
    update_queue_scan_started(scan_id)

    my_logger.info('Nessus: Adding new scan.')
    policies = get_policies()

    my_logger.info("Nessus plicies is {}".format(policies))

    policy_id = policies['Internal PCI Network Scan']
    scan_data = add(scan_name + scan_id,
                    'Create a new scan with API',
                    ips,
                    policy_id)
    nessus_scan_id = scan_data['id']

    my_logger.info('Nessus: Launching new scan.')
    nessus_scan_uuid = launch(nessus_scan_id)
    history_ids = get_history_ids(nessus_scan_id)
    history_id = history_ids[nessus_scan_uuid]
    while status(nessus_scan_id, history_id) != 'completed':
        time.sleep(25)

    my_logger.info('Nessus: Exporting the completed scan.')

    file_id = export(nessus_scan_id, history_id)
    download(nessus_scan_id, file_id)

    filename = 'nessus_{0}_{1}.nessus'.format(nessus_scan_id, file_id)
    my_logger.info("Nessus: Saving result {} with scan id {}".format(
                                    filename, scan_id))
    my_logger.info('Nessus: Logout')
    logout()

    end_time = time.time()
    run_time = end_time - start_time
    # get scan result from the downloaded file
    scan_result = get_vulnerability(filename=filename, run_time=run_time)
    my_logger.info("update the queue")

    # update the queue with scan result and the status of "san finished"
    update_queue_scan_finished(scan_id=scan_id,
                               scan_result=base64.b64encode(
                                           scan_result.encode("zlib")))

if __name__ == '__main__':
    while 1 == 1:
        the_message = claim_a_message()
        # get a message with IP address
        if (len(the_message)) > 0:
            our_scan_id = the_message[0]
            origin_id = the_message[1]
            ips = the_message[2]
            thread_scan = threading.Thread(target=nessus_scan_ips,
                                           kwargs=dict(ips=ips,
                                                       scan_id=our_scan_id))
            thread_scan.start()
        else:
            time.sleep(60)
