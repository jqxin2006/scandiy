import json
import logging
import uuid
import requests
import re
import ConfigParser
import identity

class ScanQueue(object):

    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        self.endpoint = config.get("queue", "endpoint")
        self.project_id = config.get("queue", "project_id")
        one_identity = identity.Identity()
        self.token = one_identity.get_token()

    def get_queue_messages(self, queue_name="ScanRequest", client_id=str(uuid.uuid4())):
        url = "{}/queues/{}/messages?echo=true".format(self.endpoint, queue_name)
        headers = {"Content-type" : "application/json",
                   "Accept" : "application/json",
                   "X-Auth-Token" : self.token, 
                   "X-Project-Id" : self.project_id,
                   "Client-ID" : client_id}
        resp = requests.get(url, headers=headers, verify=False)
        return resp.json()

    def claim_a_message(self, queue_name="ScanRequest", client_id=str(uuid.uuid4())):
        url = "{}/queues/{}/claims?limit=1".format(self.endpoint, queue_name)
        headers = {"Content-type" : "application/json",
                   "Accept" : "application/json",
                   "X-Auth-Token" : self.token, 
                   "X-Project-Id" : self.project_id,
                   "Client-ID" : client_id}
        payload = {"ttl":3000, "grace":3000}
        print url
        resp = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
        if resp.status_code == 201:
            claim_id = resp.headers["Location"].split("/")[-1]
            print claim_id
            resp_json = resp.json()
            return (resp_json)
        else:
            return ()


    def post_queue_message(self, queue_name="ScanRequest", client_id=str(uuid.uuid4()), body={"1":"2"}):
        url = "{}/queues/{}/messages".format(self.endpoint, queue_name)
        headers = {"Content-type" : "application/json",
                   "Accept" : "application/json",
                   "X-Auth-Token" : self.token, 
                   "X-Project-Id" : self.project_id,
                   "Client-ID" : client_id}
        payload = []
        print "*****"
        print url 
        print headers
        body["scan_id"] = str(uuid.uuid4())
        payload.append({"ttl":30000, "body":body})
        resp = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
        if resp.status_code == 201:
            return body["scan_id"]
        else:
            return "None"

    def add_thing(self, thing):
        thing['id'] = str(uuid.uuid4())
        return thing


if __name__ == '__main__':
    one_scan = ScanQueue()
    one_scan.post_queue_message()
    print one_scan.get_queue_messages()