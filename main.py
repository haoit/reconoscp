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
    path_program = os.getcwd() + "/autorecon"
    command = "python3 %s/autorecon.py %s --single-target -o  %s | tee %s" % (path_program, ip, output, output+"/scans/autorecon.log")
    run_command("AUTORECON", command, output )


if __name__ == "__main__":
    start_time = time.time()
    parser = argparse.ArgumentParser(description='OSCP Auto Enum')
    parser.add_argument('-i', '--ip', default='foobar', help="IP of target", required=True)
    args = parser.parse_args()
    ip = args.ip
    ourdir = "output/"+ip
    base_path = os.getcwd()
    path_output = os.path.abspath(ourdir)
    os.makedirs(path_output, exist_ok=True)
    threads = []


    ports,services = scan_nmap(ip, path_output)

    # search_sploit scan 
    t  = threading.Thread(target=run_searchsploit, args=(path_output,))
    t.start()
    threads.append(t)
    run_searchsploit(path_output)
    if "445" in ports:
        logger.info("[i] Enumarate SMB")
        t  = threading.Thread(target=enum_smb, args=(ip, path_output,))
        t.start()
        threads.append(t)
    if ("http" in services):
        for http_port in services["http"]:
            t  = threading.Thread(target=scan_http_service, args=(ip, http_port, "http", path_output))
            t.start()
            threads.append(t)
    if ("https" in services):
        for https_port in services["https"]:
            t  = threading.Thread(target=scan_http_service, args=(ip, https_port, "https", path_output))
            t.start()
            threads.append(t)
    t  = threading.Thread(target=run_auto_recon, args=(ip, path_output,))
    t.start()
    threads.append(t)
    while True:
        genarate_html_report(ip, base_path)
        threads = [t for t in threads if t.is_alive()]
        if len(threads) < 1:
            print("break while loop")
            break
        time.sleep(30)
        

    genarate_html_report(ip, base_path)
    genarate_checklist(ip, ports, path_output)
    logger.info("--- Finish scan with %s seconds ---" % (time.time() - start_time))



        
