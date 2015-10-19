import json
import logging
import uuid
import requests
import re
import ConfigParser


class Identity(object):

    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        self.endpoint = config.get("identity", "endpoint")
        self.username = config.get("identity", "username")
        self.apikey = config.get("identity", "apikey")


    def get_token(self):
        url = "{}/tokens".format(self.endpoint)
        headers = {"Content-type" : "application/json",
                   "Accept" : "application/json"}
        payload = {"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":self.username,"apiKey":self.apikey}}}
        
        resp = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
        

        if resp.status_code == 200:
            resp_json = resp.json()
            return resp_json["access"]["token"]["id"]
        else:
            return "none"


if __name__ == '__main__':
    one_identity = Identity()
    token = one_identity.get_token()
    print token