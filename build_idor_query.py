# import pyyaml module
from bs4 import BeautifulSoup
import re
import base64
import yaml
from yaml.loader import SafeLoader

# Open the file and load the file
#with open('UserAssetsInfo.yaml') as f:
#    data = yaml.load(f, Loader=SafeLoader)
#    print(data)

with open('sample_burp.xml', 'r') as f:
    data = f.read()
 
# Passing the stored data inside
# the beautifulsoup parser, storing
# the returned object
Bs_data = BeautifulSoup(data, "xml")
 
# Finding all instances of tag
# `unique`
b_issue = Bs_data.find_all('issue')
 
cookie = re.compile("\nCookie: .*; PHPSESSID=(.*?(?:;|\r))")

for issue in b_issue:
    base64decoded_request = base64.b64decode(issue.requestresponse.request.text).decode()
    print(issue.path.text)
    #print(base64decoded_request)
    print(cookie.findall(base64decoded_request))
    #print(re.sub("\nCookie: .*; PHPSESSID=(.*(?:;|\r))", "TAE", base64decoded_request))

