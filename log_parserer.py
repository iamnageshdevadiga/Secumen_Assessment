system_log_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
system_log_string += ' '

key_list = ["cat", "cs1", "cs2Label", "cs2", "cs3Label", "cs3", "cs4Label", "cs4", "cn1Label", "cn1", "msg", "dhost", "dst"]

def parsed_string():
    parsed_data = {}
    for key in key_list:
        parsed_data[key] = parse_key_value(key)
    return parsed_data

def parse_key_value(key, end=" "):
    start_index = system_log_string.find(key + "=")
    end_index = system_log_string[start_index:].find(end)
    field = system_log_string[start_index:start_index + end_index]
    return field.split("=", 1)[1]

parsed_data = parsed_string()
print(parsed_data)
