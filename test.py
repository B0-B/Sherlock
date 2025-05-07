import re

# Define regex patterns
ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b"

# Updated file path pattern supporting both Windows and Unix paths
path_pattern = r"^(?:[A-Za-z]:[\\/]|/)[^\0]+([\\/][^\0]+)*$"

def detect_type(string):
    if re.match(ipv4_pattern, string):
        return "IPv4 Address"
    elif re.match(ipv6_pattern, string):
        return "IPv6 Address"
    elif re.match(path_pattern, string):
        return "File Path"
    else:
        return "Unknown Type"

# Test cases
test_strings = [
    "192.168.1.1",
    "2001:0db8:85a3::8a2e:370:7334",
    "/home/user/documents",
    "C:/Users/Admin/AppData/Local/Temp/test.tmp"
]

for test in test_strings:
    print(f"{test}: {detect_type(test)}")