import json
import logging
import uuid
import requests
import re
import ConfigParser
import identity

class Test(object):

    def __init__(self):
        self.url = "http://localhost:8000"
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        self.token = config.get("test", "token")

    def post_scan(self):
        url = "{}/scans".format(self.url)
        payload = """
        {
    "environment": "ENV_NAME",
    "datetime": "1439846687",
    "id": "ff671041-b677-4da4-b901-535e689a796d",
    "servers": [
        {
            "id": "ff671041-b677-4da4-b901-535e689a796d",
            "flavor_id": "6",
            "region": "DFW",
            "hostname": "HOSTNAME",
            "os": {
                "name": "Ubuntu",
                "version": "14.04",
                "architecture": "64-bit"
            },
            "addresses": {
                "private": [
                    {
                        "addr": "10.180.1.226",
                        "version": 4
                    }
                ],
                "public": [
                    {
                        "addr": "50.56.172.247",
                        "version": 4
                    },
                    {
                        "addr": "2001:4800:780e:0510:d87b:9cbc:ff03:bbbd",
                        "version": 6
                    }
                ]
            }
        }
    ],
    "loadBalancers":[
        {
            "id": 71,
            "name":"lb-site1",
            "virtualIps":[
                {
                    "address":"206.55.130.1",
                    "type":"PUBLIC",
                    "ipVersion":"IPV4"
                }
            ]
        }
    ]
}
        """
        headers = {"Content-type" : "application/json",
                   "Accept" : "application/json",
                   "X-Auth-Token" : self.token}

        print url
        resp = requests.post(url, headers=headers, data=payload, verify=False)
        print resp.status_code
        print resp.headers
        print resp.text


if __name__ == '__main__':
    one_test = Test()
    one_test.post_scan()