import json
import xmltodict
import os
import random
import string
from loguru import logger

temp_random = []

def run_os_scandir(path_output):
    list_dir = [f.name for f in os.scandir(path_output) if f.is_dir()]
    return list_dir

def run_os_scanfile(path_folder):
    files = [f.name for f in os.scandir(path_folder) if f.is_file()]
    return files



def get_ports_from_nmap():
        path = "../portscan/nmap/%s.xml"%outfile_detail_port
    # try:
        with open(path) as f:
            xml = f.read()  
        output = json.loads(json.dumps(xmltodict.parse(xml)))
        list_port = []
        for port in output ["nmaprun"]["host"]["ports"]["port"]:
            ports = {}
            if(port["state"]["@state"] == "open"):
                ports["port"] = port["@portid"]
                ports["service"] = port["service"]
                list_port.append(ports)
        return list_port

def template_block():
    block = """
    <div class="card {{{class_name}}}">
            <div class="card-header" id="headingOne">
              <h5 class="mb-0">
                <button class="btn btn-link" data-toggle="collapse" data-target="#{{{class_toggel_block}}}" aria-expanded="true" aria-controls="collapseOne">
                 {{{name_block}}}
                </button>
              </h5>
            </div>
        
            <div id="{{{class_toggel_block}}}" class="collapse" aria-labelledby="headingOne" data-parent="#accordion-main">
              <div class="card-body">
                  {{{block_content}}}
              </div>
            </div>
        </div>
    """
    return block


def template_toggle_in_block():
    toggle = """
    <div id="{{{toggle_id}}}">
              {{{block_content}}}
    </div>
    """
    return toggle

def template_toggle_content():
    template = """
     <div class="card">
                  <div class="card-header" id="headingOne">
                    <h5 class="mb-0">
                      <button class="btn btn-link" data-toggle="collapse" data-target="#{{{toggle_target}}}" aria-expanded="true" aria-controls="collapseOne">
                        {{{toggle_name}}}
                      </button>
                    </h5>
                  </div>
              
                  <div id="{{{toggle_target}}}" class="collapse" aria-labelledby="headingOne" data-parent="#{{{toggle_id}}}">
                    <div class="card-body">
                        <code>
                        {{{toggle_content}}}
                        </code>
                    </div>
                  </div>
    </div> 
    """
    return template


def gen_nmap_report(path_output):
    report_type_1 = "NMAP ALL PORT"
    report_type_2 = "NMAP DETAIL SERVICE"
    report_type_3 = "NMAP VULN SERVICE"
    report_type_4 = "NMAP  DETAIL SERVICE NORMAL SCAN"
    report_type_5 = "TOP 50 UDP SCAN"
    toggle_id = "namp-result"

    #Gen type 1
    with open("%s/nmap/nmap-alltcp.nmap"%path_output) as f:
        output_all_port = f.read().replace("\n","</br>")
    toggle_target = "nmapallport"
    toggle_name = report_type_1
    toggle_content = output_all_port
    data_type_1 = template_toggle_content().replace("{{{toggle_target}}}", toggle_target).replace("{{{toggle_name}}}", toggle_name).replace("{{{toggle_content}}}", toggle_content).replace("{{{toggle_id}}}", toggle_id)

    #Gen type 2
    with open("%s/nmap/nmap-detail-service.nmap"%path_output) as f:
        output_all_port = f.read().replace("\n","</br>")
    toggle_target = "nmapdetailport"
    toggle_name = report_type_2
    toggle_content = output_all_port
    data_type_2 = template_toggle_content().replace("{{{toggle_target}}}", toggle_target).replace("{{{toggle_name}}}", toggle_name).replace("{{{toggle_content}}}", toggle_content).replace("{{{toggle_id}}}", toggle_id)

   #Gen type 3
    with open("%s/nmap/nmap-vuln-port.nmap"%path_output) as f:
        output_all_port = f.read().replace("\n","</br>")
    toggle_target = "nmapvulnport"
    toggle_name = report_type_3
    toggle_content = output_all_port
    data_type_3 = template_toggle_content().replace("{{{toggle_target}}}", toggle_target).replace("{{{toggle_name}}}", toggle_name).replace("{{{toggle_content}}}", toggle_content).replace("{{{toggle_id}}}", toggle_id)

    # #Gen type 4
    # with open("%s/nmap/nmap-detail-service-v1.nmap"%path_output) as f:
    #     output_all_port = f.read().replace("\n","</br>")
    # toggle_target = "nmapdetailservicev1"
    # toggle_name = report_type_4
    # toggle_content = output_all_port
    # data_type_4 = template_toggle_content().replace("{{{toggle_target}}}", toggle_target).replace("{{{toggle_name}}}", toggle_name).replace("{{{toggle_content}}}", toggle_content).replace("{{{toggle_id}}}", toggle_id)

    # #Gen type 5
    # with open("%s/nmap/nmap-top20-udp.nmap"%path_output) as f:
    #     output_all_port = f.read().replace("\n","</br>")
    # toggle_target = "nmaptopudp"
    # toggle_name = report_type_5
    # toggle_content = output_all_port
    # data_type_5 = template_toggle_content().replace("{{{toggle_target}}}", toggle_target).replace("{{{toggle_name}}}", toggle_name).replace("{{{toggle_content}}}", toggle_content).replace("{{{toggle_id}}}", toggle_id)

    block_content = data_type_1 + data_type_2 + data_type_3  
    data = template_toggle_in_block().replace("{{{toggle_id}}}", toggle_id).replace("{{{block_content}}}", block_content)
    return data

def gen_random_string():
    global temp_random
    randomstring = ''.join(random.choices(string.ascii_uppercase , k=32))
    while True:
        if randomstring in temp_random:
            randomstring = ''.join(random.choices(string.ascii_uppercase , k=32))
        else:
            break
    return randomstring


def genarate_html_from_forlder(namefolder , path_folder):
    files = run_os_scanfile(path_folder)
    block_content = ""
    toggle_id = gen_random_string()
    for i in files:
        with open("%s/%s" % (path_folder, i)) as f:
            file_content = f.read()
        if len(file_content) > 1:
            toggle_name = i
            toggle_target = gen_random_string()
            toggle_content = file_content.replace('\n','</br>')
            data_type = template_toggle_content().replace("{{{toggle_target}}}", toggle_target).replace("{{{toggle_name}}}", toggle_name).replace("{{{toggle_content}}}", toggle_content).replace("{{{toggle_id}}}", toggle_id)
            block_content += data_type
    
    data = template_toggle_in_block().replace("{{{toggle_id}}}", toggle_id).replace("{{{block_content}}}", block_content)
    
    class_name = gen_random_string()
    class_toggel_block = gen_random_string()
    name_block = namefolder
    block_content = data

    data = template_block().replace("{{{class_name}}}", class_name).replace("{{{class_toggel_block}}}", class_toggel_block).replace("{{{name_block}}}", name_block).replace("{{{block_content}}}", block_content)
    return data
    

def genarate_html_report(ip, base_path):
    path_output = os.getcwd() +"/output/%s/" % ip
    list_dir = run_os_scandir(path_output)
    print(list_dir)
    list_dir.remove('nmap')
    data_detail = ""
    for folder in list_dir:
        if len(os.listdir(path_output + folder)) != 0:
            data_detail += genarate_html_from_forlder(folder, path_output + folder)


    #Gen report 
    with open(base_path+"/modules/templates/index.template") as f:
        template = f.read() 

    with open(os.getcwd()+ "/output/%s/index.html"%ip,"w") as f:
        nmap_content = gen_nmap_report(path_output)
        # nmap_content = "xxx"
        template = template.replace("{{{IP}}}",ip).replace("{{{nmap_content}}}",nmap_content).replace("{{{data_detail}}}",data_detail)
        f.write(template)
    logger.info("[i] Genarate report done. Check report file in %s" % os.getcwd() + "/output/%s/index.html"%ip)

