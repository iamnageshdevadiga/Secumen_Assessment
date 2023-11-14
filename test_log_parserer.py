import pytest
from log_parserer import processed_string

def test_string_parserer():
    """
        Test function for the 'parsed_string' method in the log_parserer module.
        It checks if the 'parsed_string' method correctly parses a given system log string and returns the expected result.
        
    """
    # Input system log string
    input_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
    input_string += ' '
    
    # Expected result after parsing
    expected_output = {
                "cat": "C2",
                "cs1": "DNS_TUNNELING",
                "cs2Label": "vueUrls",
                "cs1Label": "subcat",
                "cs2": "https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650",
                "cs3Label": "Tags",
                "cs3": "USA,Finance",
                "cs4Label": "Url",
                "cs4": "https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323",
                "cn1Label": "severityScore",
                "cn1": "900",
                "msg": "Malicious activity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS",
                "dhost": "bad.com",
                "dst": "1.1.1.1"
            }
    
    #parsed string
    result = processed_string(input_string)
    
    # Assertion to check if the result matches the expected result
    assert result == expected_output

def test_invalid_input_string():
    """
    Test case to check the behavior of the 'processed_string' function when provided with an invalid input string.

    Input:
    - Invalid string without key and value pairs.

    Expected Output:
    - An empty dictionary since the input string doesn't contain any key andvalue pairs.
    """
    input_string = "Invalid string without key and value pairs"
    
    # Dictionary contains empty data
    expected_output = {}

    #parsed string 
    result = processed_string(input_string)
    
    # Assertion to check if the result matches the expected result
    assert result == expected_output

def test_valid_input_string_with_missing_key_pair():
    """
    Test case to check the behavior of the 'processed_string' function when a valid input string is missing a key-value pair.

    Input:
    - Input system log string doesn't contain "cs1Label=subcat".

    Expected Output:
    - Dictionary with the parsed key and value pairs. The missing key, in this case, "cs1Label", should have the value "None".
    """
    # Input system log string
    input_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
    input_string += ' '
    
    # Dictionary contains empty data
    expected_output = {
            "cat": "C2",
            "cs1": "DNS_TUNNELING",
            "cs2Label": "vueUrls",
            "cs1Label": "None",
            "cs2": "https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650",
            "cs3Label": "Tags",
            "cs3": "USA,Finance",
            "cs4Label": "Url",
            "cs4": "https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323",
            "cn1Label": "severityScore",
            "cn1": "900",
            "msg": "Malicious activity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS",
            "dhost": "bad.com",
            "dst": "1.1.1.1"
        }

    #parsed string 
    result = processed_string(input_string)
    
    # Assertion to check if the result matches the expected result
    assert result == expected_output

if __name__ == "__main__":
    pytest.main()
