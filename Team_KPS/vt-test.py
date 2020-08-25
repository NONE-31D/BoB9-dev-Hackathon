import os
import errno
import sys

from multiprocessing import Process, Queue

from collections import deque
import requests
import json
import time



args = ""
for i, arg in enumerate(sys.argv):
    if i == 0:
        continue
    args += arg
    args += " "

def network_miner():
    print(args)
    os.system("sudo ./network-miner "+args)

def mkdir_output():
    try:
        if not(os.path.isdir("./output/")):
            os.makedirs(os.path.join("./output/"))
    except OSError as e:
        if e.errno != errno.EEXIST:
            print("Failed to create directory!!!!!")
            raise

def file_catcher():
    # path = "./output/"
    path = "./"
    init_filelist = os.listdir(path)
    while(1):
        curr_filelist = os.listdir(path)
        get_report()

        if len(curr_filelist) > len(init_filelist):
            diff = list(set(curr_filelist) - set(init_filelist))
        else:
            init_filelist = curr_filelist
            continue
        
        
        if len(diff) != 0:
            for file_name in diff:
                print(file_name)
                file_analysis(path, file_name)
            init_filelist = curr_filelist

def file_analysis(path, file_name):
    VT_KEY = "0c2e807ef97a2650138e664959c159fa03ed317bab5bca5ac2651d3b0ab32d27"
    
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {'apikey': VT_KEY}

    files = {'file': (file_name, open(path+file_name, 'rb'))}

    response = requests.post(url, files=files, params=params)

    res_json = response.json()
    print(res_json['resource'])
    md5_queue.append(res_json['resource'])


def file_analysis_result(md5):
    VT_KEY = "0c2e807ef97a2650138e664959c159fa03ed317bab5bca5ac2651d3b0ab32d27"

    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': VT_KEY , 'resource': md5}

    response = requests.get(url, params=params)

    scan_result = response.json()
    print('\033[1m'+"SCAN RESULT ==================================================="+'\033[0m')

    for key, val in scan_result.items():
        if key == "scans":
            for key2, val2 in val.items():
                is_bold = '\033[0m'
                if val2['detected']:
                    is_bold = '\033[1m'
                print(is_bold+f"{key2:20} detection ==> {val2['detected']}"+'\033[0m')
            print()
            continue
        print(f"**{key}**")
        print(val)
        print()
    


def get_report():
    if md5_queue:
        md5 = md5_queue.popleft()
        file_analysis_result(md5)
        #print(report)
    time.sleep(0.1)

md5_queue = deque()
if __name__ == "__main__":
    file_catcher()