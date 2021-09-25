import os
import argparse
from loguru import logger
import time
from  modules.scanports import *
from  modules.searchsploit import *
from  modules.smbenum import *
from  modules.untils import *
from modules.templates.genarate_html_report import *
from modules.http_scan import *
from modules.cheklist_resouce.genarate_checklist import *
import threading 
import time


def init_scan():
    if not os.path.exists("output"):
        os.makedirs("output")
    else:
        pass
        # os.rmdir("output")
        # os.makedirs("output")
def run_auto_recon(ip, output):
    rootdir = os.path.dirname(os.path.realpath(__file__))
    path_program = rootdir + "/autorecon"
    command = "python3 %s/autorecon.py %s --single-target -o  %s | tee %s" % (path_program, ip, output, output+"/scans/autorecon.log")
    run_command("AUTORECON", command, output )

def full_scan(ip, extentions):
    start_time = time.time()
    ourdir = "output/"+ip
    base_path = os.path.dirname(os.path.realpath(__file__))
    path_output = os.path.abspath(ourdir)
    os.makedirs(path_output, exist_ok=True)
    threads = []
    ports,services = scan_nmap(ip, path_output)
    print(services)
    # search_sploit scan 
    t  = threading.Thread(target=run_searchsploit, args=(path_output,))
    t.start()
    threads.append(t)
    if "445" in ports:
        logger.info("[i] Enumarate SMB")
        t  = threading.Thread(target=enum_smb, args=(ip, path_output,))
        t.start()
        threads.append(t)
    if ("http" in services):
        for http_port in services["http"]:
            t  = threading.Thread(target=scan_http_service, args=(ip, http_port, "http", path_output, extentions))
            t.start()
            threads.append(t)
    if ("https" in services):
        for https_port in services["https"]:
            t  = threading.Thread(target=scan_http_service, args=(ip, https_port, "https", path_output, extentions))
            t.start()
            threads.append(t)
    t  = threading.Thread(target=run_auto_recon, args=(ip, path_output,))
    t.start()
    threads.append(t)
    while True:
        genarate_html_report(ip, base_path)
        genarate_checklist(ip, ports, path_output)
        threads = [t for t in threads if t.is_alive()]
        if len(threads) < 1:
            break
        time.sleep(30)
    
    genarate_html_report(ip, base_path)
    genarate_checklist(ip, ports, path_output)
    logger.info("--- Finish scan with %s seconds ---" % (time.time() - start_time))

def genarate_report(ip):
    logger.info("--- Start genarate report---")
    start_time = time.time()
    ourdir = "output/"+ip
    base_path = os.path.dirname(os.path.realpath(__file__))
    path_output = os.path.abspath(ourdir)
    os.makedirs(path_output, exist_ok=True)
    ports,servcies = get_nmap_port_list(path_output + "/nmap", ip)
    genarate_html_report(ip, base_path)
    genarate_checklist(ip, ports, path_output)
    logger.info("--- Finish task with %s seconds ---" % (time.time() - start_time))

def nmap_scan_only(ip):
    start_time = time.time()
    ourdir = "output/"+ip
    base_path = os.path.dirname(os.path.realpath(__file__))
    path_output = os.path.abspath(ourdir)
    os.makedirs(path_output, exist_ok=True)
    ports,services = scan_nmap(ip, path_output)
    genarate_html_report(ip, base_path)
    genarate_checklist(ip, ports, path_output)
    logger.info("--- Finish scan with %s seconds ---" % (time.time() - start_time))

def screenshot_manual(files,ip):
    start_time = time.time()
    ourdir = "output/" + ip  
    base_path = os.path.dirname(os.path.realpath(__file__))
    path_output = os.path.abspath(ourdir)
    output_screenshots_manual = path_output + "/manual_screenshots"
    os.makedirs(path_output, exist_ok=True)
    screenshot_url('manual', output_screenshots_manual, "", files)
    genarate_html_report(ip, base_path)
    logger.info("--- Finish screenshots with %s seconds ---" % (time.time() - start_time))    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OSCP Auto Enum')
    parser.add_argument('-i', '--ip', help="IP of target", required=True)
    parser.add_argument('-sc', '--screenshot', default='foobar', help="Mode manual screenshot", required=False)
    parser.add_argument('-m', '--mode', default='1', help="1. Full Enum, 2. Report, 3.Nmap Only, 4.Screenshot", required=True)
    parser.add_argument('-f', '--files', help="file targer", required=False)
    parser.add_argument('-ef', '--extentions', help="Extentions file scan for ffuf", required=False)
    args = parser.parse_args()
    mode = args.mode
    ip = args.ip
    extentions = ".txt,.php,.aspx" #Default extentions
    if args.extentions:
        extentions = args.extentions
    if mode == "1":
        full_scan(ip, extentions)
    elif mode == "2":
        genarate_report(ip)
    elif mode == "3":
        nmap_scan_only(ip)
    elif mode == "4":
        relative_path = args.files

        if os.path.exists(relative_path):
            screenshot_manual(os.path.abspath(relative_path),ip)
        else:
            print("Cannot find " + relative_path)
            exit(1)   
    else:
        print("Invalid mode.")



    


    



        
