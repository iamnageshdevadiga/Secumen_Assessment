#This Python script designed to parse antivirus system log strings and extract key information..

import json

def check_string_contains_key_value_pairs(input_string, delimiter=' '):
    """
    Check if the given string contains key and value pairs.

    Parameters:
    - input_string (str): The input string to check.
    - delimiter (str, optional): The delimiter between key-value pairs.

    Returns:
    - bool: True if key-value pairs are found, False otherwise.

    Example:
     # check_string_contains_key_value_pairs("data=obj1 a=b")
        True
     #check_string_contains_key_value_pairs("This is a invalid string not contained any key value pair.")
        False
    """
    key_value_pairs = input_string.split(delimiter)
    
    for pair in key_value_pairs:
        if '=' in pair:
            # if at least one key-value pair is found then  return True
            return True

    # if no key-value pair is found then return False
    return False

def processed_string(input_string):
    """
    Parse a set of key-value pairs from an input string and store them in a dictionary.

    Parameters:
    - input_string (str): The input string containing key-value pairs.

    Returns:
    - dict: A dictionary containing parsed key-value pairs based on the provided key list.

    Example:
    >>> input_str = "cat=C2 cs1Label=subcat cs1=DNS_TUNNELING msg=Malicious activity dhost=bad.com"
    >>> parsed_string(input_str)
    {'cat': 'C2', 'cs1Label': 'subcat', 'cs1': 'DNS_TUNNELING', 'msg': 'Malicious activity', 'dhost': 'bad.com'}
    
    """
    
    parsed_data = {}
    if not check_string_contains_key_value_pairs(input_string):
        return parsed_data
    key_list = ["cat", "cs1", "cs2Label","cs1Label", "cs2", "cs3Label", "cs3", "cs4Label", "cs4", "cn1Label", "cn1", "msg", "dhost", "dst"]
    
    for key in key_list:
        parsed_data[key] = parse_key_value(input_string,key)
    return parsed_data

def parse_key_value(input_string,key, end=" "):
    """
    Parse a specific key-value pair from an input string.

    Parameters:
    - input_string (str): The input string containing key-value pairs.
    - key (str): The key to extract from the input string.
    - end (str, optional): The delimiter indicating the end of the value. Default is a space.

    Returns:
    - str or int : The parsed value corresponding to the given key.

    Example:
    input_str = "msg=Malicious activity was reported. dhost=bad.com"
    parse_key_value(input_str, "msg")
    'Malicious activity was reported'
    parse_key_value(input_str, "dhost")
    'bad.com'
    
    """
    
    if key+'=' in input_string:
        if key == "msg":
            initial_index = input_string.find(key  + "=")
            value = input_string[initial_index + len(key) + 1:].split('.')[0]
            return ' '.join(value.split(end, 1))
        
        initial_index = input_string.find(key+"=")
        final_index = input_string[initial_index:].find(end)
        final_string = input_string[initial_index:final_index+initial_index]
        return final_string.split("=",1)[1]
    
    else:
        return "None"

if __name__ == "__main__":
    system_log_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
    system_log_string+=' '
    parsed_data = processed_string(system_log_string)
    print(json.dumps(parsed_data,indent=4))
