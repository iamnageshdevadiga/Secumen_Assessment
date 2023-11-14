import pytest
from log_parserer import parsed_string

def test_parsed_string():
    input_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"
    input_string += ' '

    expected_result = {
                "cat": "C2",
                "cs1": "DNS_TUNNELING",
                "cs2Label": "vueUrls",
                "cs2": "https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650",
                "cs3Label": "Tags",
                "cs3": "USA,Finance",
                "cs4Label": "Url",
                "cs4": "https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323",
                "cn1Label": "severityScore",
                "cn1": 900,
                "msg": "Maliciousactivity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS",
                "dhost": "bad.com",
                "dst": "1.1.1.1"
            }
    
    result = parsed_string(input_string)
   
    assert result == expected_result

if __name__ == "__main__":
    pytest.main()
