'''Sends requests to server defined in testing_requests.json'''

import requests
import json

with open('testing_requests.json', 'r') as f:
    reqs = json.load(f)

for req in reqs:
    requests.request(**req)