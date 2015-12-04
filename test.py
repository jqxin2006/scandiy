import json
import logging
import uuid
import requests
import re
import ConfigParser
import identity
import queue


class Test(object):

    def __init__(self):
        self.url = "http://localhost:8000"
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        self.token = config.get("test", "token")

    def get_queue_messages(scan_id="cb6399bb-3e8d-4d0f-8fd9-6bc22a969839"):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        client_id = config.get("nessus", "client_id")
        the_scan = queue.ScanQueue()
        the_messages = the_scan.get_queue_messages(queue_name="ScanResponse",
                                                   client_id=client_id)
        number_messages = 0

        if len(the_messages) > 0:
            the_messages_list = the_messages["messages"]
            number_messages = len(the_messages_list)
            for message in the_messages_list:
                print message

        print "There are {} messages".format(number_messages)

    def post_scan(self):
        url = "{}/scans".format(self.url)
        payload = """
        {
            "id": "fa6d55a9-269e-4203-8309-046f6c109e47",
            "targets": "23.253.105.129,166.78.174.158"
        }
        """
        headers = {"Content-type": "application/json",
                   "Accept": "application/json",
                   "X-Auth-Token": self.token}

        print url
        resp = requests.post(url, headers=headers, data=payload, verify=False)
        print resp.status_code
        print resp.headers
        print resp.text


if __name__ == '__main__':
    one_test = Test()
    one_test.get_queue_messages()
