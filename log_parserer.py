import json

def parsed_string(input_string):
    parsed_data = {}
    key_list = ["cat", "cs1", "cs2Label", "cs2", "cs3Label", "cs3", "cs4Label", "cs4", "cn1Label", "cn1", "msg", "dhost", "dst"]
    for key in key_list:
        parsed_data[key] = parse_key_value(input_string,key)
    return parsed_data

def parse_key_value(input_string,key, end=" "):
    if key == "msg":
        start_index = input_string.find(key + "=")
        value = input_string[start_index + len(key) + 1:].split('.')[0]
        return ''.join(value.split(end, 1))
    
    else:
        start_index = input_string.find(key + "=")
        end_index = input_string[start_index:].find(end)
        field = input_string[start_index:start_index + end_index]
        value = field.split("=", 1)[1]
        return  int(value) if value.isdigit() else value

if __name__ == "__main__":
    system_log_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
    system_log_string += ' '
    parsed_data = parsed_string(system_log_string)
    print(json.dumps(parsed_data,indent=4))
