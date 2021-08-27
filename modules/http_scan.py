import os
from loguru import logger
import threading
from . untils import * 
import time

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
# nikto
# sslscan
# Scan cms
# aquatone
# wpscan 


def dirsearch_scan(url, directory_output):
    time.sleep(20)
    output = directory_output + Fileoutput_Dirsearch
    command = "dirsearch  -u %s -o %s" % (url,  output)
    run_command("DIRSEARCH", command, output)
    # info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}')

def ffuf_scan(url, directory_output):
    output = directory_output + Fileoutput_Dirsearch
    #ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.37/FUZZ -t 50 - o test.log
    command = "ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u %s/FUZZ -t 50 -o %s" % (url,  directory_output + Fileoutput_FFUF)
    run_command("FFUF", command, output)

def nikto_scan(url, directory_output):
    output = directory_output + Fileoutput_Dirsearch
    command = "nikto -ask=no -h %s | tee %s" % (url,  directory_output + Fileoutput_nikto)
    run_command("NIKTO", command, output)


def whatweb_scan(url, directory_output):
    output = directory_output + Fileoutput_Dirsearch
    command = "whatweb  %s | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | tee -a  %s" % (url,  directory_output + Fileoutput_whatweb)
    run_command("WHATWEB", command, output)

def nmap_http_scan(port, ip,  directory_output):
    output = directory_output + Fileoutput_nmap
    command = "nmap -sV -p %s --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)'  %s | tee -a  %s" % (port, ip,   output)
    run_command("NMAP-HTTP", command, output)

def aqua_tools():
    pass

def curl_robots(url, directory_output):
    output = directory_output + Fileoutput_curlrobots
    command = "curl -sSik %s/robots.txt -m 10 | tee -a %s" % (url,  directory_output + Fileoutput_curlrobots)
    run_command("CURL-ROBOTS.TXT", command, output)

def scan_http_service(ip, port, scheme, path_out):
    directory_output = path_out + "/" + scheme + "-" + port
    if (port == "80" ) or (port == "443"):
        url = "%s://%s"%(scheme, ip)
    else:
        url = "%s://%s:%s"%(scheme, ip, port) 
    init_scan(directory_output)
    logger.info("[!] Start scan HTTP Service %s." % url)
    thread_1  = threading.Thread(target=dirsearch_scan, args=(url, directory_output,))
    thread_2  = threading.Thread(target=ffuf_scan, args=(url, directory_output,))
    thread_3  = threading.Thread(target=whatweb_scan, args=(url, directory_output,))
    thread_4  = threading.Thread(target=nmap_http_scan, args=(port, ip , directory_output,))
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



