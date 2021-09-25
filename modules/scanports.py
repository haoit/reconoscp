import subprocess
import os
import xmltodict
import json
from loguru import logger
import threading
import requests


outfile_all_port = "nmap-alltcp"
outfile_top_udp = "nmap-top20-udp"
outfile_detail_port = "nmap-detail-service"
outfile_detail_port_v1 = "nmap-detail-service-v1"
outfile_vuln_port = "nmap-vuln-port"
host_seem_down = False

def get_nmap_port_list(directory_output, ip):
        services = {}
        path = "%s/%s.xml" % (directory_output, outfile_all_port)
    # try:
        with open(path) as f:
            xml = f.read()
        # print(xml)  
        output = json.loads(json.dumps(xmltodict.parse(xml)))
        #print(output)
        list_port = []
        http_service = []
        https_service = []
        print(output["nmaprun"]["host"]["ports"])
        if isinstance(output["nmaprun"]["host"]["ports"]["port"], list):
            # print(len(output["nmaprun"]["host"]["ports"]["port"]))
            # print(output["nmaprun"]["host"]["ports"]["port"])
            # print("run here")
            for port in output["nmaprun"]["host"]["ports"]["port"]:
                if(port["state"]["@state"] == "open"):
                    list_port.append(port["@portid"])
                    try:
                        if port["service"]["@name"] == "https":
                            https_service.append(port["@portid"])
                        elif "http" in port["service"]["@name"] :
                            http_service.append(port["@portid"])
                    except:
                        pass
                    if (port["@portid"] not in http_service) and (port["@portid"] not in https_service):
                        port_type = check_http_port(ip, port["@portid"])
                        if port_type == "http":
                            http_service.append(port["@portid"])
                        elif port_type == "https":
                            https_service.append(port["@portid"])
        else:
            port = output["nmaprun"]["host"]["ports"]["port"]
            if(port["state"]["@state"] == "open"):
                list_port.append(port["@portid"])
                try:
                    if port["service"]["@name"] == "https":
                        https_service.append(port["@portid"])
                    elif "http" in port["service"]["@name"] :
                        http_service.append(port["@portid"])
                    else:
                        port_type = check_http_port(ip, port["@portid"])
                        if port_type == "http":
                            http_service.append(port["@portid"])
                        elif port_type == "https":
                            https_service.append(port["@portid"])
                except:
                    pass
                if (port["@portid"] not in http_service) and (port["@portid"] not in https_service):
                    port_type = check_http_port(ip, port["@portid"])
                    if port_type == "http":
                        http_service.append(port["@portid"])
                    elif port_type == "https":
                        https_service.append(port["@portid"])

        services["http"] = http_service
        services["https"] = https_service
        print(services)
        return list_port,services
    # except:
    #     print("Error when open file output nmap %s" % outfile_all_port)

def check_http_port(ip, port):
    print("check port %s" % port)
    try:
        url = "http://%s:%s" %(ip, port)
        r = requests.get(url, verify=False, timeout=10) # 10 seconds
        return "http"
    except Exception as e:
        print(e)
        try:
            url = "https://%s:%s" %(ip, port)
            r = requests.get(url, verify=False, timeout=10) # 10 seconds
            return "https"
        except Exception as e:
            print(e)
            pass
    return "other"
    


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
    global host_seem_down
    #nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.161
    if host_seem_down:
        command = "nmap -p- --min-rate 10000 -Pn -oA %s/%s %s" % (directory_output,outfile_all_port, ip)
    else:
        command = "nmap -p- --min-rate 10000 -oA %s/%s %s" % (directory_output,outfile_all_port, ip)
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan all port using command: <yellow>%s</yellow> ." % command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
        if "Host seems down" in line.decode("utf8"):
            if not host_seem_down:
                host_seem_down = True
                logger.error("[!] Host seem down try with -Pn options.")
                scan_all_tcp_port(directory_output, ip)
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )
    return get_nmap_port_list(directory_output, ip)

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

def scan_top_20_udp(directory_output, ip):
    command = "nmap -sU -A --top-ports=20 --version-all -oA %s/%s %s" % (directory_output,outfile_top_udp, ip)
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan all port using command: <yellow>%s</yellow> ." % command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )


def scan_detail_service_v1(directory_output, ip):
    global host_seem_down
    if host_seem_down:
        command = "nmap -sC -sV -Pn -oA %s/%s %s" % (directory_output, outfile_detail_port_v1, ip)
    else:
        command = "nmap -sC -sV -oA %s/%s %s" % (directory_output, outfile_detail_port_v1, ip)
    logger.opt(colors=True).info("[i] Starting scan service detail using command: <yellow>%s</yellow> ." % command)
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )

def scan_detail_service(directory_output, ip, ports):
    global host_seem_down
    if(ports):
        list_port = ",".join(ports)
        if host_seem_down:
            command = "nmap -sC -sV -Pn -p %s -oA %s/%s %s" % (list_port, directory_output, outfile_detail_port, ip)
        else:
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
    global host_seem_down
    if(ports):
        list_port = ",".join(ports)
        if host_seem_down:
            command = "nmap -p %s --script vuln -Pn -oA %s/%s %s" % (list_port, directory_output, outfile_vuln_port, ip)
        else:
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
    ports1,services = scan_all_tcp_port(directory_output_nmap, ip)
    ports2 = naabu_scan(directory_output_naabu,ip)
    ports = list(set(ports1) | set(ports2))
    scan_detail_service_v1(directory_output_nmap, ip)
    thread_detail  = threading.Thread(target=scan_detail_service, args=(directory_output_nmap, ip, ports))
    thread_vuln  = threading.Thread(target=scan_vuln_service, args=(directory_output_nmap, ip, ports))
    # thread_udp  = threading.Thread(target=scan_top_20_udp, args=(directory_output_nmap, ip, ports))
    thread_detail.start()
    thread_vuln.start()
    # thread_udp.start()
    thread_detail.join()
    logger.info("[i] Finish Nmap scan.")
    return ports,services
