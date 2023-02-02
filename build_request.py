# import pyyaml module
from bs4 import BeautifulSoup
import re
import base64
import yaml
import json
import argparse
import requests
from copy import copy
from yaml.loader import SafeLoader

result = []
path = []

def get_keys(data, target, array=False):
    if(array):
        for v in data:
            if isinstance(v, dict):
                get_keys(v, target)
            if isinstance(v, list):
                get_keys(v, target, array=True)    
            if str(v) == target:
                result.append(copy(path))
    else:
        for k, v in data.items():
            path.append(k)
            if isinstance(v, dict):
                get_keys(v, target)
            if isinstance(v, list):
                get_keys(v, target, array=True)  
            if str(v) == target:
                result.append(copy(path))
            path.pop()
    return result

#get headers of profile_id from UserAuthenticationConfig.yaml
def get_authentication_headers(profile_id, header_name):
    with open('UserAuthenticationConfig.yml') as f:
        data = yaml.load(f, Loader=SafeLoader)
        for user in data:
            if(str(user['id']) == profile_id):
                for header in user['authentication_headers']:
                    if header_name in header:
                        for k, v in header[header_name].items():
                            if isinstance(v, int):
                                header[header_name][k] = str(header[header_name][k])
                        return header[header_name]

def get_edges(value):
    with open('UserAssetsInfo.yml') as f:
        data = yaml.load(f, Loader=SafeLoader)
        for user in data:
            return get_keys(user, value)

def get_associate_id(edges, target_profile_id):
    print(edges)
    with open('UserAssetsInfo.yml') as f:
        data = yaml.load(f, Loader=SafeLoader)
        for user in data:
            if(str(user['id']) == target_profile_id):
                return user[edges];               

def get_csrf_token_endpoint(profile_id):
    with open('UserAuthenticationConfig.yml') as f:
        data = yaml.load(f, Loader=SafeLoader)
        for user in data:
            if(str(user['id']) == profile_id):
                return user['csrf_token']['config']['endpoint']

def get_csrf_matcher_regex(profile_id):
    with open('UserAuthenticationConfig.yml') as f:
        data = yaml.load(f, Loader=SafeLoader)
        for user in data:
            if(str(user['id']) == profile_id):
                return user['csrf_token']['config']['matcher_regex']
def get_searcher_cookie(profile_id):
    with open('UserAuthenticationConfig.yml') as f:
        data = yaml.load(f, Loader=SafeLoader)
        for user in data:
            if(str(user['id']) == profile_id):
                for k, v in user['searcher']['config']['cookies'].items():
                    return k + "=" + str(v)

def get_csrf_token(profile_id):
    url = get_csrf_token_endpoint("100000619818670")
    matcher_regex = get_csrf_matcher_regex("100000619818670")
    cookies = get_authentication_headers("100000619818670", "Cookie")
    response = requests.get(url, cookies = cookies)
    token = re.search(r'' + matcher_regex + '', response.text)
    return token.group(1)
                

def process_header_match(match):
    #Replace the value of a chosen cookie(group 1) from the whole match(group 0) 
    return match.group(0).replace(match.group(1), "TAE")

#def process_parameter_match(match):
#    return match.group

with open('sample_burp.xml', 'r') as f:
    data = f.read()
    Bs_data = BeautifulSoup(data, "xml")
    b_issue = Bs_data.find_all('issue')


if(__name__ == "__main__"):
    parser = argparse.ArgumentParser()
    parser.add_argument('-profile', dest='profile_id', type=str, help='')
    args = parser.parse_args()

    if(isinstance(args.profile_id, str)):
        with open('sample_burp.xml', 'r') as f:
            data = f.read()
            Bs_data = BeautifulSoup(data, "xml")
            b_issue = Bs_data.find_all('issue')
            cookie = get_searcher_cookie(args.profile_id)

            for issue in b_issue:
                base64decoded_request = base64.b64decode(issue.requestresponse.request.text).decode()
                print(issue.path.text)
                search_via_cookie_result = re.search('Cookie:(?=.*(' + cookie + '(?:;|\r|\n|$|\s))).+', base64decoded_request)
                if search_via_cookie_result is None:
                    continue
                x = get_edges("422352436")
                print(x[0][0])
                #print(get_associate_id(get_edges("422352436"), "10000064562"))
                #print(re.sub('(username=.*?&).+', lambda match: process_parameter_match(match), base64decoded_request))
                cookie = re.compile('Cookie:(?=.*PHPSESSID=(.*?(?:;|\r|\n))).+')
            
