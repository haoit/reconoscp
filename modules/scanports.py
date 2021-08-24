import subprocess
import os
import xmltodict
import json
from loguru import logger
import threading


outfile_all_port = "nmap-alltcp"
outfile_detail_port = "nmap-detail-service"
outfile_detail_port_v1 = "nmap-detail-service-v1"
outfile_vuln_port = "nmap-vuln-port"


def get_nmap_port_list(directory_output):
        path = "%s/%s.xml" % (directory_output, outfile_all_port)
    # try:
        with open(path) as f:
            xml = f.read()  
        output = json.loads(json.dumps(xmltodict.parse(xml)))
        list_port = []
        for port in output ["nmaprun"]["host"]["ports"]["port"]:
            if(port["state"]["@state"] == "open"):
                list_port.append(port["@portid"])
        return list_port
    # except:
    #     print("Error when open file output nmap %s" % outfile_all_port)

def get_naabu_port_list(directory_output):
    path = "%s/%s" % (directory_output, "naabu.log")
    ports = []
    with open(path) as f:
        lines = f.readlines()
    for line in lines:
        port = line.strip('\n').split(":")[1]
        ports.append(port)
    return ports


def scan_all_tcp_port(directory_output, ip):
    #nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.161
    command = "nmap -p- --min-rate 10000 -oA %s/%s %s" % (directory_output,outfile_all_port, ip)
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan all port using command: <yellow>%s</yellow> ." % command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )
    return get_nmap_port_list(directory_output)

def naabu_scan(directory_output,ip):
      #nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.161
    final_command = "naabu -host %s -o %s/%s" % (ip, directory_output,"naabu.log")
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan all port using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT NAABU======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT NAABU======================================]</blue>\n\n" )
    return get_naabu_port_list(directory_output)


def scan_detail_service_v1(directory_output, ip):
    #nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA scans/nmap-tcpscripts 10.10.10.161
        command = "nmap -sC -sV -oA %s/%s %s" % (directory_output, outfile_detail_port_v1, ip)
        logger.opt(colors=True).info("[i] Starting scan service detail using command: <yellow>%s</yellow> ." % command)
        p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
        for line in p.stdout.readlines():
            print(line.decode("utf8")),
        retval = p.wait()
        logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )

def scan_detail_service(directory_output, ip, ports):
    #nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA scans/nmap-tcpscripts 10.10.10.161
    if(ports):
        list_port = ",".join(ports)
        command = "nmap -sC -sV -p %s -oA %s/%s %s" % (list_port, directory_output, outfile_detail_port, ip)
        logger.opt(colors=True).info("[i] Starting scan service detail using command: <yellow>%s</yellow> ." % command)
        p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
        for line in p.stdout.readlines():
            print(line.decode("utf8")),
        retval = p.wait()
        logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )
    else:
        logger.error("No port to run")
    pass

def scan_vuln_service(directory_output, ip, ports):
    #nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA scans/nmap-tcpscripts 10.10.10.161
    if(ports):
        list_port = ",".join(ports)
        command = "nmap -p %s --script vuln -oA %s/%s %s" % (list_port, directory_output, outfile_vuln_port, ip)
        logger.opt(colors=True).info("[i] Starting scan vuln service using command: <yellow>%s</yellow> ." % command)
        p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
        for line in p.stdout.readlines():
            print(line.decode("utf8")),
        retval = p.wait()
        logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )
    else:
        logger.error("No port to run")
    pass

def scan_nmap(ip, path_output):
    directory_output_nmap = path_output + "/nmap"
    directory_output_naabu = path_output + "/naabu"
    if not os.path.exists(directory_output_nmap):
        os.makedirs(directory_output_nmap)
    if not os.path.exists(directory_output_naabu):
        os.makedirs(directory_output_naabu)
    ports1 = scan_all_tcp_port(directory_output_nmap, ip)
    ports2 = naabu_scan(directory_output_naabu,ip)
    ports = list(set(ports1) | set(ports2))
    scan_detail_service_v1(directory_output_nmap, ip)
    thread_detail  = threading.Thread(target=scan_detail_service, args=(directory_output_nmap, ip, ports))
    thread_vuln  = threading.Thread(target=scan_vuln_service, args=(directory_output_nmap, ip, ports))
    thread_detail.start()
    thread_vuln.start()
    thread_detail.join()
    thread_vuln.join()
    logger.info("[i] Finish Nmap scan.")
    return ports
