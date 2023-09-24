from flask import Flask, render_template, request
from typing import Tuple, Union, Any
import pandas as pd
import numpy as np
import re
from tld import get_tld
import pickle
from urllib.parse import urlparse

blacklist = pd.read_csv('blacklist.csv')
blacklist


def check_blacklist(url):
    if url in blacklist['url'].values:
         return True
    else:
         return False
    
with open("rf.pkl", "rb") as file:
    model = pickle.load(file)


# url='https://www.youtube.com/'


def is_url_ip_address(url: str) -> bool:
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0


def process_tld(url,fix_protos):
    res = get_tld(url, as_object = True, fail_silently=False, fix_protocol=fix_protos)
    domain = res.domain    
    return domain
    
def process_url_with_tld(url,ip):
    try:
        if ip == 0:
            if str(url).startswith('http:'):
                return process_tld(url)
            else:
                return process_tld(url, fix_protos=True)
        else:
            domain = None
            return domain
    except:

        return 0

def check_domain(domain_name):
    domain_=pd.read_csv('dataset/cleaned_url.csv')
    res=1
    for x in range(len(domain_)):
        safe_domain=domain_.iloc[x].values[6]
        if domain_name==safe_domain:
            id_ =domain_.iloc[x].values[0]
            safe=domain_.iloc[id_].values[3]
            if safe==0:
                res=0
                return res
            elif safe==1:
                res=1
                return res
            else:
                pass
        else:
                pass
            

def get_url_path(url: str) -> Union[str, None]:
    try:
        res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        if res.parsed_url.query:
            joined = res.parsed_url.path + res.parsed_url.query
            return joined
        else:
            return res.parsed_url.path
    except:
        return None


def alpha_count(url: str) -> int:
    alpha = 0
    for i in url:
        if i.isalpha():
            alpha += 1
    return alpha


def digit_count(url: str) -> int:
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


def count_dir_in_url_path(url_path: Union[str, None]) -> int:
    if url_path:
        n_dirs = url_path.count('/')
        return n_dirs
    else:
        return 0


def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def check_url(url):
    ip = is_url_ip_address(url)
    hostname_length = len(urlparse(url).netloc)
    path_length = len(urlparse(url).path)
    domain_name =process_url_with_tld(url,ip)
    fld_length = fd_length(url)
    feature_1 = url.count('-')
    feature_2 = url.count('@')
    feature_3 = url.count('?')
    feature_4 = url.count('%')
    feature_5 = url.count('.')
    feature_6 = url.count('=')
    http = url.count('http')
    https = url.count('https')
    feature_7 = url.count('www')
    digits = digit_count(url)
    letters = alpha_count(url)
    dri = count_dir_in_url_path(url)

    output = [hostname_length, path_length, fld_length, feature_1, feature_2, feature_3, feature_4, feature_5, feature_6, http, https, feature_7, digits, letters, dri, ip]
    #print(output)
    features = np.array([output]) 
    result_=check_domain(domain_name)
    print(result_)
    dd=pd.read_csv('cleaned_url.csv')
    if result_==0:
        if url in dd['url'].values: 
            pred_test = model.predict(features)
            test=pred_test[0]
            result = ''
            if pred_test[0] ==0:
                result = 'Safe'
                return result
            else:
                result = 'Not Safe'
                return result
        else:
            return 'Safe'
    else:
        pred_test = model.predict(features)
        print(pred_test[0])
        result = ''
        if pred_test[0] ==0:
            result = 'Safe'
        else:
            result = 'Not Safe'
        return result



def data_update(url, label):
        df = pd.read_csv('whitelist.csv')
        if url not in df.values:
            df.loc[len(df.index)] = [url, label]
            df.to_csv("whitelist.csv", index=False)
            return
        else:
            print("\nThis value exists in Dataframe")


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/url_check', methods=['GET', 'POST'])
def url_check():
    if request.method == 'POST':
        url = request.form.get('link')
        blacklist=check_blacklist(url)
        if blacklist:
            res = ['This URL is Blacklisted ']
            return render_template('home.html', data=res)
        else:
            
            blacklist='This URL is not in Blacklist DataBase '
            cmd=''
            result=''
            wd=pd.read_csv('whitelist.csv')
            if url in wd['url'].values:
                for x in range(len(wd)):
                    if wd.iloc[x].values[0]==url:
                        safe=wd.iloc[x].values[1]
                        if safe=='Safe':
                            result='Safe'
                        elif safe=='Not Safe':
                            result='Not Safe'
                        else:
                            pass
            else:
                result = check_url(url)
                data_update(url, result)
            if result =='Safe':
                    cmd='This url is Safe to use'
            else:
                    cmd='It is not safe to use'
            res=[blacklist,cmd]
            return render_template('home.html', data=res)


if __name__ == '__main__':
    app.run(debug=True)
