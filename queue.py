import json
import logging
import uuid
import requests
import re
import ConfigParser
import identity


class ScanQueue(object):

    def __init__(self, my_logger=None):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        self.my_logger = my_logger
        self.endpoint = config.get("queue", "endpoint")
        self.project_id = config.get("queue", "project_id")
        my_logger.info("trying to call identity to get token")
        one_identity = identity.Identity(my_logger=my_logger)
        self.token = one_identity.get_token()
        my_logger.info("got the token!")

    def get_queue_messages(self,
                           queue_name="ScanRequest",
                           client_id=str(uuid.uuid4())):
        url = "{}/queues/{}/messages?echo=true&limit=100".format(
                                          self.endpoint, queue_name)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json",
                   "X-Auth-Token": self.token,
                   "X-Project-Id": self.project_id,
                   "Client-ID": client_id}
        try:
            resp = requests.get(url, headers=headers, verify=False)
        except Exception as ex:
            self.my_logger.error(ex)

        if resp.status_code == 204:
            return {}
        else:
            return resp.json()

    def delete_queue_message(self,
                             queue_name="ScanRequest",
                             client_id=str(uuid.uuid4()),
                             message_id=""):
        url = "{}/queues/{}/messages/{}".format(self.endpoint,
                                                queue_name,
                                                message_id)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json",
                   "X-Auth-Token": self.token,
                   "X-Project-Id": self.project_id,
                   "Client-ID": client_id}
        try:
            resp = requests.delete(url, headers=headers, verify=False)
        except Exception as ex:
            self.my_logger.error(ex)
        if resp.status_code == 204:
            return {}
        else:
            return resp.json()

    def claim_a_message(self,
                        queue_name="ScanRequest",
                        client_id=str(uuid.uuid4())):
        url = "{}/queues/{}/claims?limit=1".format(self.endpoint, queue_name)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json",
                   "X-Auth-Token": self.token,
                   "X-Project-Id": self.project_id,
                   "Client-ID": client_id}
        payload = {"ttl": 3000, "grace": 3000}
        self.my_logger.debug("the url is: {}".format(url))
        try:
            resp = requests.post(
                            url,
                            headers=headers,
                            data=json.dumps(payload),
                            verify=False)
        except Exception as ex:
            self.my_logger.error(ex)

        if resp.status_code == 201:
            claim_id = resp.headers["Location"].split("/")[-1]
            self.my_logger.debug("claim_id is {}".format(claim_id))
            resp_json = resp.json()
            return (resp_json)
        else:
            return ()

    def release_a_claim(self,
                        queue_name="ScanRequest",
                        client_id=str(uuid.uuid4()),
                        claim_id=""):
        url = "{}/queues/{}/claims/{}".format(self.endpoint,
                                              queue_name,
                                              claim_id)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json",
                   "X-Auth-Token": self.token,
                   "X-Project-Id": self.project_id,
                   "Client-ID": client_id}
        try:
            resp = requests.delete(url, headers=headers, verify=False)
        except Exception as ex:
            self.my_logger.error(ex)

        if resp.status_code == 204:
            return True
        else:
            return False

    def post_queue_message(self,
                           scan_id="none",
                           queue_name="ScanRequest",
                           client_id=str(uuid.uuid4()),
                           body={"1": "2"}):
        url = "{}/queues/{}/messages".format(self.endpoint, queue_name)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json",
                   "X-Auth-Token": self.token,
                   "X-Project-Id": self.project_id,
                   "Client-ID": client_id}
        payload = []
        if scan_id == "none":
            body["scan_id"] = str(uuid.uuid4())
        else:
            body["scan_id"] = scan_id

        payload.append({"ttl": 30000, "body": body})
        try:
            resp = requests.post(
                            url,
                            headers=headers,
                            data=json.dumps(payload),
                            verify=False)
        except Exception as ex:
            self.my_logger.error(ex)

        self.my_logger.debug("status code is: {}".format(resp.status_code))
        self.my_logger.debug("resp.text is: {}".format(resp.text))
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
