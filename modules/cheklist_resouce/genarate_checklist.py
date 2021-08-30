import yaml
import json
import random
import string
import os

temp_random = []

def gen_random_string():
    global temp_random
    randomstring = ''.join(random.choices(string.ascii_uppercase , k=32))
    while True:
        if randomstring in temp_random:
            randomstring = ''.join(random.choices(string.ascii_uppercase , k=32))
        else:
            break
    return randomstring

def template_block(name, notes, jsmind_container_id, manual_id, manual_text, refer_id, refer_list):
    temp_data = """
    <div class="card">
          <div class="card-header">
            <h2>{{{name}}}</h2>
            <span class="badge badge-warning">{{{notes}}}</span>
          </div>
          <div class="card-body">
            <div id="{{{jsmind_container_id}}}" class='jsmind_container'></div>
            <div id="accordion">
                <div class="card">
                  <div class="card-header" id="headingOne">
                    <h5 class="mb-0">
                      <button class="btn btn-link" data-toggle="collapse" data-target="#{{{manual_id}}}" aria-expanded="true" aria-controls="collapseOne">
                        Manual to do
                      </button>
                    </h5>
                  </div>
              
                  <div id="{{{manual_id}}}" class="collapse" aria-labelledby="headingOne" data-parent="#accordion">
                    <div class="card-body">
                        <code>
                            {{{manual_text}}}
                        </code>
                    </div>
                  </div>

               </div>  <!-- End block nmap -->
               <div class="card">
                <div class="card-header" id="headingOne">
                  <h5 class="mb-0">
                    <button class="btn btn-link" data-toggle="collapse" data-target="#{{{refer_id}}}" aria-expanded="true" aria-controls="collapseOne">
                        Refer
                    </button>
                  </h5>
                </div>
            
                <div id="{{{refer_id}}}" class="collapse" aria-labelledby="headingOne" data-parent="#accordion">
                  <div class="card-body">
                        <ul>
                        {{{refer_list}}}
                        </ul>
                  </div>
                </div>
             </div>
              
              </div>

          </div>
        </div>
    """
    return temp_data.replace("{{{name}}}",name).replace("{{{notes}}}",notes).replace("{{{jsmind_container_id}}}",jsmind_container_id).replace("{{{manual_id}}}",manual_id).replace("{{{manual_text}}}",manual_text).replace("{{{refer_id}}}",refer_id).replace("{{{refer_list}}}",refer_list)

def template_refer_list(list_url):
    temp_data=""
    print(list_url)
    for url in list_url:
        temp_data += '<li><a href="%s" target="_blank">%s</a></li>'%(url,url)
    print(temp_data)
    return temp_data

def template_script_mindmap(mind_var, data, options_var, jsmind_container_id):
    temp_data="""
    var {{{mind_var}}} = {
          "meta":{
              "name":"todo_list",
              "author":"honghao96@gmail.com",
              "version":"0.2",
          },
          "format":"node_array",
          "data": {{{data}}}
      };
      var {{{options_var}}} = {
          container:'{{{jsmind_container_id}}}',
          editable:true,
          theme:'primary'
      }
      jsMind.show({{{options_var}}},{{{mind_var}}});
    """
    return temp_data.replace("{{{mind_var}}}", mind_var).replace("{{{data}}}", data).replace("{{{options_var}}}", options_var).replace("{{{jsmind_container_id}}}", jsmind_container_id)

def tempalte_child_tree(root_id, data):
    child_id = gen_random_string()
    tmp_link = ""
    final_data = []
    temp = {}
    if data["link"]:
        tmp_link = "<a href='%s' target='_blank' class='fa fa-external-link'></a>" %  data["link"]
    name = data["name"] + tmp_link
    temp["id"] = child_id
    temp["parentid"] = root_id
    temp["topic"] = "<input type='checkbox'> %s " % name
    final_data.append(temp)
    if len(data["children"] )> 0:
        for i in data["children"]:
            final_data += tempalte_child_tree(child_id, i)
    return final_data

def get_tree_mindmap(data):
    root_tree = {"id":"root", "isroot":1, "topic":"%s" % data["name"]}
    tmp_list = []
    tmp_list.append(root_tree)
    if len(data["children"]):
        for child in data["children"]:
            tmp_list +=tempalte_child_tree("root", child)
    return tmp_list
def genarate_checklist(ip, services, path_output):
    scipt_js = ""
    data_block = ""

    base_path = os.path.dirname(os.path.realpath(__file__))
    with open("%s/port_checklist.yaml"%base_path, 'r') as yaml_in:
        checklist = yaml.safe_load(yaml_in)
    for item in checklist:
        is_show = False
        for i in services:
            if i in item['port'].split(','):
                is_show = True
        if is_show:
            data_mind =get_tree_mindmap(item)
            mind_var = gen_random_string()
            options_var = gen_random_string()
            jsmind_container_id = gen_random_string()
            manual_id = gen_random_string()
            refer_id = gen_random_string()

            scipt_js += template_script_mindmap(mind_var, json.dumps(data_mind), options_var, jsmind_container_id )
            refer_list = template_refer_list(item["refer"])
            data_block += template_block(item["name"], item["notes"], jsmind_container_id, manual_id, item["data_manual"].replace("<ip address>",ip), refer_id, refer_list)

    with open("%s/checklist.template" % base_path) as f:
        template = f.read() 

    with open("%s/checklist.html"%path_output,"w") as f:
        template = template.replace("{{{data_block}}}",data_block).replace("{{{data_js}}}",scipt_js).replace("{{{base_path}}}",base_path)
        f.write(template)
