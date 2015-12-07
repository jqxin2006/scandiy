import json
import logging
import uuid
import requests
import re
import ConfigParser


class Identity(object):

    def __init__(self, my_logger=None):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        self.my_logger = my_logger
        self.endpoint = config.get("identity", "endpoint")
        self.username = config.get("identity", "username")
        self.apikey = config.get("identity", "apikey")

    def get_token(self):
        url = "{}/tokens".format(self.endpoint)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        payload = {"auth": {"RAX-KSKEY:apiKeyCredentials":
                   {"username": self.username,
                    "apiKey": self.apikey}}}
        try:
            resp = requests.post(
                            url,
                            headers=headers,
                            data=json.dumps(payload),
                            verify=False)
        except Exception as ex:
            self.my_logger.error(ex)
        self.my_logger.info("Connect to identity to get a token")
        if resp.status_code == 200:
            resp_json = resp.json()
            self.my_logger.info("successful token")
            return resp_json["access"]["token"]["id"]
        else:
            self.my_logger.info("failed token")
            return "none"


if __name__ == '__main__':
    one_identity = Identity()
    token = one_identity.get_token()
