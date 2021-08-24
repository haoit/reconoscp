import os
from loguru import logger
from  modules.scanports import *
from  modules.searchsploit import *
from  modules.smbenum import *
from modules.templates.gen_report import *
def init_scan():
    if not os.path.exists("output"):
        os.makedirs("output")
    else:
        pass
        # os.rmdir("output")
        # os.makedirs("output")

if __name__ == "__main__":
    ip = '10.10.10.161'
    base_path = os.getcwd()
    path_output = base_path + "/output/"
    ports = scan_nmap(ip, path_output)
    print("Done scan nmap")
    run_searchsploit(path_output)
    if "445" in ports:
        logger.info("[i] Enumarate SMB")
        enum_smb(ip ,path_output)
    genarate_html_report(ip, base_path)


        
