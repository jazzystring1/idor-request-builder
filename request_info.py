# import pyyaml module
from bs4 import BeautifulSoup
import re
import base64
import yaml
import argparse
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
 
cookie = re.compile('Cookie:(?=.*PHPSESSID=(.*?(?:;|\r|\n))).+')

def process_header_match(match):
    #Replace the value of a chosen cookie(group 1) from the whole match(group 0) 
    return match.group(0).replace(match.group(1), "TAE")

#def process_parameter_match(match):
#    return match.group
    
for issue in b_issue:
    base64decoded_request = base64.b64decode(issue.requestresponse.request.text).decode()
    print(issue.path.text)
    #print(base64decoded_request)
    #print(cookie.findall(base64decoded_request))
    print(re.sub('Cookie:(?=.*PHPSESSID=(.*?(?:;|\r|\n|$))).+', lambda match: process_header_match(match), base64decoded_request))

    #print(re.sub('(username=.*?&).+', lambda match: process_parameter_match(match), base64decoded_request))

if(__name__ == "__main__"):
    parser = argparse.ArgumentParser()
    parser.add_argument('--parameters', dest='parameters', type=str, help='List endpoints that match with given parameter')
    args = parser.parse_args()

    print (args.parameters)