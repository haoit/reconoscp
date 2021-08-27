import subprocess
import os
import xmltodict
import json
from loguru import logger

directory_output = "searchsploit"
outfile_detail_port = "nmap-detail-service"



def get_ports_from_nmap(out_path):
        file_path = "%s/nmap/%s.xml"% (out_path, outfile_detail_port)
    # try:
        with open(file_path) as f:
            xml = f.read()  
        output = json.loads(json.dumps(xmltodict.parse(xml)))
        print(output)
        list_port = []
        if (type(output["nmaprun"]["host"]["ports"]["port"]).__name__ == 'dict'):
            ports = {}
            if(output["nmaprun"]["host"]["ports"]["port"]["state"]["@state"] == "open"):
                ports["port"] = output["nmaprun"]["host"]["ports"]["port"]["@portid"]
                ports["service"] = output["nmaprun"]["host"]["ports"]["port"]["service"]
                list_port.append(ports)
        else:
            for port in output["nmaprun"]["host"]["ports"]["port"]:
                print("port here")
                print(port)
                ports = {}
                if(port["state"]["@state"] == "open"):
                    ports["port"] = port["@portid"]
                    ports["service"] = port["service"]
                    list_port.append(ports)
        return list_port

def init_scan_searchsploit(out_path):
    if not os.path.exists(out_path + directory_output):
        os.makedirs(out_path + directory_output)

def remove_none_file(path_folder):
    command = """grep -Ril "Exploits: No Results" %s | xargs rm -f"""%path_folder
    subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def searchsploit_service(port, out_path ,nameservice, version=''):
    #searchsploit apache tomcat 2.4
   
    final_command = "searchsploit %s %s | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | tee -a %s/%s" % (nameservice, version, out_path + directory_output, port)
    save_command = "echo searchsploit %s %s | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' |tee -a %s/%s" % (nameservice, version, out_path + directory_output, port)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)    
    logger.opt(colors=True).info("[i] Start searchsploit: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT SEARCHSPLOIT======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT SEARCHSPLOIT======================================]</blue>\n\n" )

def run_searchsploit(out_path):    
    init_scan_searchsploit(out_path)
    try:
        service = get_ports_from_nmap(out_path)
        for port in service:
            if ("@name" in port["service"]) and ("@version" in port["service"]):
                searchsploit_service(port["port"], out_path, port["service"]["@name"], port["service"]["@version"])
            if ("@name" in port["service"]):
                searchsploit_service(port["port"], out_path, port["service"]["@name"])
        remove_none_file(out_path + "/" + directory_output)
    except:
        pass