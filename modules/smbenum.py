import subprocess
import os
import xmltodict
import json
from loguru import logger
import threading

host_seem_down = False

def init_scan_smb(directory_output):
    if not os.path.exists( directory_output):
        os.makedirs( directory_output)

def enumerate_hostname(ip, directory_output):
    #Enumerate Hostname nmblookup -A [ip]
    command = "nmblookup -A %s" % ip
    final_command = "%s | tee -a %s/nmblookup.log" % ( command,  directory_output)
    save_command = "echo %s | tee -a %s/nmblookup.log" % ( command, directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan nmblookup using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT nmblookup======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT nmblookup======================================]</blue>\n\n" )

def nmap_scan_smb(ip, directory_output):
    global host_seem_down

    if host_seem_down:
        final_command = "nmap --script smb-enum-shares -p 139,445 %s | tee -a %s/list_share_nmap.log" % (ip , directory_output)
    else:
        final_command = "nmap -Pn --script smb-enum-shares -p 139,445 %s | tee -a %s/list_share_nmap.log" % (ip , directory_output)
    save_command = "echo nmap --script smb-enum-shares -p 139,445 %s | tee -a %s/list_share_nmap.log" % (ip , directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan Nmap using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT NMAP======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
        if "Host seems down" in line.decode("utf8"):
            if not host_seem_down:
                host_seem_down = True
                logger.error("[!] Host seem down try with -Pn options.")
                nmap_scan_smb(ip, directory_output)
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT NMAP======================================]</blue>\n\n" )

    #Check for Vulnerabilities - nmap --script smb-vuln* -p 139,445 [ip]
    if host_seem_down:
        final_command = "nmap -Pn --script smb-vuln* -p 139,445 %s | tee -a %s/nmap_smb_vuln.log" % (ip ,  directory_output)
    else:
        final_command = "nmap --script smb-vuln* -p 139,445 %s | tee -a %s/nmap_smb_vuln.log" % (ip ,  directory_output)        
    save_command = "echo nmap --script smb-vuln* -p 139,445 %s | tee -a %s/nmap_smb_vuln.log" % (ip , directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan nmap using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT nmap======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT nmap======================================]</blue>\n\n" )


def enumerate_list_shares(ip, directory_output):
    #List Shares
    #smbmap -H [ip/hostname]
    final_command = "smbmap -H %s | tee -a %s/list_share_smbmap.log" % (ip ,  directory_output)
    save_command = "echo smbmap -H %s | tee -a %s/list_share_smbmap.log" % ( ip,  directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan smbmap using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT smbmap======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT smbmap======================================]</blue>\n\n" )
   
   #echo exit | smbclient -L \\\\[ip]
    final_command = "echo exit | smbclient -L \\\\%s | tee -a %s/list_share_smbclient.log" % (ip , directory_output)
    save_command = "echo 'echo exit | smbclient -L \\\\%s' | tee -a %s/list_share_smbclient.log" % (ip ,  directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan smbclient using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT smbclient======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT smbclient======================================]</blue>\n\n" )

  
    #crackmapexecsmb10.10.10.10-u''-p''--shares
    final_command = "crackmapexec smb %s -u '' -p '' --shares | tee -a %s/crackmapexec_1.log" % (ip , directory_output)
    save_command = "echo crackmapexec smb %s -u '' -p '' --shares | tee -a %s/crackmapexec_1.log" % (ip , directory_output)

    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan crackmapexec using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT crackmapexec======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT crackmapexec======================================]</blue>\n\n" )

    #crackmapexec smb 10.10.10.10 -u 'sa' -p '' --shares
    final_command = "crackmapexec smb %s -u 'sa' -p '' --shares | tee -a %s/crackmapexec_2.log" % (ip , directory_output)
    save_command = "echo crackmapexec smb %s -u 'sa' -p '' --shares | tee -a %s/crackmapexec_2.log" % (ip ,  directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan crackmapexec using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT crackmapexec======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT crackmapexec======================================]</blue>\n\n" )

    #crackmapexec smb 10.10.10.10 -u 'sa' -p 'sa' --shares
    final_command = "crackmapexec smb %s -u 'sa' -p 'sa' --shares | tee -a %s/crackmapexec_3.log" % (ip ,  directory_output)
    save_command = "echo crackmapexec smb %s -u 'sa' -p 'sa' --shares | tee -a %s/crackmapexec_3.log" % (ip , directory_output)    
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan crackmapexec using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT crackmapexec======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT crackmapexec======================================]</blue>\n\n" )



def check_null_sessions(ip,  directory_output):
     #smbmap nullsessions -H [ip/hostname]
    final_command = "smbmap -H %s -u null | tee -a %s/smbmap_nullsessions.log" % (ip , directory_output)
    save_command = "echo smbmap -H %s -u null | tee -a %s/smbmap_nullsessions.log" % (ip ,  directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan smbmap using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT smbmap======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT smbmap======================================]</blue>\n\n" )

    #Enumerate echo enumdomusers rpcclient -U "" -N [ip]
    final_command = "echo enumdomusers | rpcclient -U '' -N %s | tee -a %s/rpc_nullsessions1.log" % (ip ,  directory_output)
    save_command = "echo 'echo enumdomusers | rpcclient -U '' -N %s' | tee -a %s/rpc_nullsessions1.log" % (ip ,  directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan rpcclient using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT rpcclient======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT rpcclient======================================]</blue>\n\n" )

    #Enumerate echo enumdomgroups rpcclient -U "" -N [ip]
    command = "echo enumdomgroups | rpcclient -U '' -N %s | tee -a %s/rpc_nullsessions2.log" % (ip ,  directory_output)
    save_command = "echo 'echo enumdomgroups | rpcclient -U '' -N %s' | tee -a %s/rpc_nullsessions2.log" % (ip ,  directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan rpcclient using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT rpcclient======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT rpcclient======================================]</blue>\n\n" )


    
def Overall_Scan(ip, directory_output):
    #Overall Scan - enum4linux -a [ip]
    final_command = "enum4linux -a %s | tee -a %s/enum4linux.log" % (ip ,  directory_output)
    save_command = "echo enum4linux -a %s | tee -a %s/enum4linux.log" % (ip ,  directory_output)
    subprocess.Popen(save_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(final_command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan enum4linux using command: <yellow>%s</yellow> ." % final_command)
    logger.opt(colors=True).info("<blue>[================================OUTPUT enum4linux======================================]</blue>\n\n" )
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT enum4linux======================================]</blue>\n\n" )

def enum_smb(ip ,path_output):
    directory_output = path_output + "/SMB_139-445"
    init_scan_smb(directory_output) 
    thread_1  = threading.Thread(target=enumerate_hostname, args=(ip, directory_output,))
    thread_2  = threading.Thread(target=enumerate_list_shares, args=(ip, directory_output,))
    thread_3  = threading.Thread(target=check_null_sessions, args=(ip, directory_output,))
    thread_4  = threading.Thread(target=nmap_scan_smb, args=(ip, directory_output, ))
    thread_5  = threading.Thread(target=Overall_Scan, args=(ip, directory_output,))
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


    
    
    # enumerate_hostname(ip,directory_output)
    # enumerate_list_shares(ip, directory_output)
    # check_null_sessions(ip, directory_output)
    # check_Vulnerabilities(ip, directory_output)
    # Overall_Scan(ip, directory_output)