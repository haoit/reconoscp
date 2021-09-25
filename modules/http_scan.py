import os
from posix import listdir
from loguru import logger
import threading
from . untils import * 
import time
import random
import requests
from urllib.parse import unquote, urlparse

base_dir = "/media/psf/Home/projects/oscp_auto/modules/"
Fileoutput_Dirsearch = "/dirsearch.log"
Fileoutput_FFUF = "/ffuf.log"
Fileoutput_nikto = "/nikto.log"
Fileoutput_whatweb = "/whatweb.log"
Fileoutput_nmap = "/nmaphttp.log"
Fileoutput_curlrobots = "/robots.txt"
### 
#Tools use :
# dirsearch
# ffuf
# whatweb
# Scan cms
# wkhtmltoimage


def dirsearch_scan(url, directory_output):
    time.sleep(random.randint(30,50))
    output = directory_output + Fileoutput_Dirsearch
    command = "dirsearch  -u %s -o %s" % (url,  output)
    run_command("DIRSEARCH", command, output)
    screenshot_url("dirsearch", directory_output, url)
    # info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}')

def ffuf_scan(url, directory_output, extentions):
    output = directory_output + Fileoutput_FFUF
    command = "ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u %s/FUZZ -t 60 -sf -e %s | grep -v '#' | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | tee -a %s" % (url, extentions,  directory_output + Fileoutput_FFUF)
    run_command("FFUF", command, output)
    screenshot_url("ffuf", directory_output, url)

def nikto_scan(url, directory_output):
    output = directory_output + Fileoutput_nikto
    command = "nikto -ask=no -h %s | tee %s" % (url,  directory_output + Fileoutput_nikto)
    run_command("NIKTO", command, output)


def whatweb_scan(url, directory_output):
    output = directory_output + Fileoutput_whatweb
    command = "whatweb  %s | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | tee -a  %s" % (url,  directory_output + Fileoutput_whatweb)
    run_command("WHATWEB", command, output)

def nmap_http_scan(port, ip,  directory_output):
    output = directory_output + Fileoutput_nmap
    command = "nmap -sV -p %s --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)'  %s | tee -a  %s" % (port, ip,   output)
    run_command("NMAP-HTTP", command, output)

def parse_dirsearch_result(directory_output):
    #cat dirsearch.log | grep -E '^200|^301' | tr -s ' ' | awk -F " " '{print $2","$3}'
    output = []
    dirsearch_log_file = directory_output + Fileoutput_Dirsearch
    command = """cat %s | grep -E '^200|^301' | tr -s ' ' | awk -F " " '{print $3}'""" % dirsearch_log_file
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        output.append(line.decode("utf-8").strip())
    retval = p.wait()
    return output

def screenshot_url(type, directory_output, url , file_url=None):
    if type == "dirsearch":
        output = parse_dirsearch_result(directory_output)
        for i in output:
            url = i
            wkhtmltoimage(url, directory_output +"/screenshots")
    elif type == "ffuf":
        files = [bytes.fromhex(f.name.split('.')[0]).decode('utf-8') for f in os.scandir(directory_output + '/screenshots') if f.is_file()]
        list_url_dirsearch = [item.split('||')[0].replace(":443/",'/').replace(":80/",'/') for item in files]
        output = parse_ffuf_result(directory_output, url)
        for i in output:            
            if (i not in  list_url_dirsearch) and (i+"/" not in  list_url_dirsearch):
                wkhtmltoimage(i, directory_output +"/screenshots")
    elif type == "manual":
        with open(file_url) as file:
            array = file.readlines()
        for url in array:
            wkhtmltoimage(url.strip(), directory_output)



def parse_ffuf_result(directory_output, url):
    #cat ffuf.log | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | grep -v "^ffuf" | tr -s ' ' | awk -F ' ' '{print $1}'
    #head -n 1 ffuf.log | awk -F ' ' '{print $5}' | sed 's/FUZZ//g'

    output = []
    ffuf_log_file = directory_output + Fileoutput_FFUF
    command = """cat %s | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | grep -v "^ffuf"  | tr -s ' ' | awk -F ' ' '{print $1}'""" % ffuf_log_file
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line_value = line.decode("utf-8").strip()
        if line_value:
            output.append(line_value) 
    retval = p.wait()
    list_url = [url + "/" + x for x in output]
    return list_url
    

#wkhtmltoimage --format png https://10.10.10.60/system-users.txt screen1.png
def wkhtmltoimage(url, directory_output):
    os.makedirs(directory_output, exist_ok=True)
    r = requests.get(url, verify=False)
    url = r.url
    if len(r.content) > 1024:
        size_respone = str(int(len(r.content)/1024)) + "KB"
    else:
        size_respone = str(len(r.content)) + "B"
    respone_status = r.status_code
    file_image_name ="%s||%s||%s" % (url, respone_status, size_respone)
    file_image_name = file_image_name.encode("utf-8").hex() 
    output = directory_output +"/" +  file_image_name + ".png"
    command = "wkhtmltoimage --format png %s %s " % (url, output)
    thread  = threading.Thread(target=run_command, args=("wkhtmltoimage", command, output , False))
    thread.start()


def curl_robots(url, directory_output):
    output = directory_output + Fileoutput_curlrobots
    command = "curl -sSik %s/robots.txt -m 10 | tee -a %s" % (url,  directory_output + Fileoutput_curlrobots)
    run_command("CURL-ROBOTS.TXT", command, output)



def scan_http_service(ip, port, scheme, path_out, extentions=".txt,.php,.aspx"):
    logger.info("Using extentions: %s" % extentions)
    directory_output = path_out + "/" + scheme + "-" + port
    if (str(port) == "80" ) or (str(port) == "443"):
        url = "%s://%s"%(scheme, ip)
    else:
        url = "%s://%s:%s"%(scheme, ip, port) 
    init_scan(directory_output)
    logger.info("[!] Start scan HTTP Service %s." % url)
    thread_1  = threading.Thread(target=dirsearch_scan, args=(url, directory_output,))
    thread_2  = threading.Thread(target=ffuf_scan, args=(url, directory_output,extentions))
    thread_3  = threading.Thread(target=whatweb_scan, args=(url, directory_output,))
    thread_4  = threading.Thread(target=nikto_scan, args=(url , directory_output,))
    thread_5  = threading.Thread(target=curl_robots, args=(url, directory_output,))

    thread_1.start()
    thread_2.start()
    thread_3.start()
    thread_4.start()
    thread_5.start()

    thread_1.join()
    thread_2.join()
    thread_3.join()
    thread_4.join()
    thread_5.join()


