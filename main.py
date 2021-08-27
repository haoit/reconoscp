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


    # 1
        

    genarate_html_report(ip, base_path)
    logger.info("--- Finish scan with %s seconds ---" % (time.time() - start_time))



        
