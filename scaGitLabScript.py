import json
import argparse
import re

def modify_schema(string_to_add, packageName, fingerprint, packageType, description, properties, ruleId, version):
    schema = {
        "version": "15.0.0",
        "vulnerabilities": [
        {
            "id": "0e8294b7f5226e2e75d8369e100cd610face57ef67bc1af625ddb250785726a7",
            "name": "Deserialization of Untrusted Data Semgrep",
            "description": "In Apache Log4j.",
            "cve": "",
            "severity": "Critical",
            "solution": "Please review Semgrep SCA rule",
            "location": {
            "dependency_files": "pom.xml",
            "dependency": {
                "package": {
                "name": "org.apache.logging.log4j/log4j-core"
                },
                "version": "2.6.1"
            }
            },
            "identifiers": [
            {
                "type": "gemnasium",
                "name": "Gemnasium-ef60b3d6-926c-472f-b24a-f585deccf8b6",
                "value": "ef60b3d6-926c-472f-b24a-f585deccf8b6",
                "url": "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/blob/master/maven/org.apache.logging.log4j/log4j-core/CVE-2017-5645.yml"
            },
            {
                "type": "cve",
                "name": "CVE-2017-5645",
                "value": "CVE-2017-5645",
                "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5645"
            },
            {
                "type": "ghsa",
                "name": "GHSA-fxph-q3j8-mv87",
                "value": "GHSA-fxph-q3j8-mv87",
                "url": "https://github.com/advisories/GHSA-fxph-q3j8-mv87"
            }
            ],
            "links": [
            {
                "url": "http://www.openwall.com/lists/oss-security/2019/12/19/2"
            }
            ],
            "details": {
            "vulnerable_package": {
                "type": "text",
                "name": "Vulnerable Package",
                "value": "org.apache.logging.log4j/log4j-core:2.6.1"
            }
            }
        }
        ],
        "scan": {
        "analyzer": {
            "id": "gemnasium-maven",
            "name": "Semgrep",
            "url": "https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium",
            "vendor": {
            "name": "GitLab"
            },
            "version": "4.1.0"
        },
        "scanner": {
            "id": "gemnasium-maven",
            "name": "Semgrep",
            "url": "https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium",
            "vendor": {
            "name": "GitLab"
            },
            "version": "4.1.0"
        },
        "type": "dependency_scanning",
        "start_time": "2023-07-20T14:54:46",
        "end_time": "2023-07-20T14:55:01",
        "status": "success"
        }
    }

    def add_value_to_required_key(schema_dict, string_to_add, packageName, fingerprint, packageType, description, properties, ruleId, version, indent=0):
        for key, value in schema_dict.items():
            
            if key == 'id' and '0e8294b7f5226e2e75d8369e100cd610face57ef67bc1af625ddb250785726a7' in value:
                schema_dict[key] = fingerprint

            if key == 'name' and 'Deserialization of Untrusted Data Semgrep' in value:
                schema_dict[key] = packageName.replace('\"', '').replace(':', '').replace(' ', '').replace('{', '')
            
            # Check for 'type' keys with a string value and set to packageType
            if key == 'description' and 'In Apache Log4j.' in value:
                schema_dict[key] = description
            
            #Check for 'type' key with a string value and set to description
            if key == 'description' and isinstance(value, str) and "Identifies the vulnerability's location." in value:
                schema_dict[key] = value.replace("Identifies the vulnerability's location.", description)
            
            #Check for 'type' key with a string value and set to reachable
            if key == 'severity' and 'Critical' in value and properties == 'reachable':
                schema_dict[key] = 'Critical'
            elif key == 'severity' and 'Critical' in value and properties != 'reachable':
                schema_dict[key] = 'High'
            
            #Append rule to text in solution
            if key == 'solution' and 'Please review Semgrep SCA rule' in value:
                textInSolution = [value, ruleId]
                joinedText = ' '.join(textInSolution)
                schema_dict[key] = joinedText
            
            #Change the value of the dependency file
            if key == 'dependency_files' and 'pom.xml' in value:
                schema_dict[key] = string_to_add
            
            #change the package name 
            if key == 'name' and 'org.apache.logging.log4j/log4j-core' in value:
                schema_dict[key] = string_to_add
            
            if key == 'version' and '2.6.1' in value:
                schema_dict[key] = version

            if isinstance(value, dict):
                add_value_to_required_key(value, string_to_add, packageName, fingerprint, packageType, description, properties, ruleId, version, indent+1)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        add_value_to_required_key(item, string_to_add, packageName, fingerprint, packageType, description, properties, ruleId, version, indent+1)
    add_value_to_required_key(schema, string_to_add, packageName, fingerprint, packageType, description, properties, ruleId, version)

    # Save the modified schema to a file
    with open('gl-dependency-scanning-report.json', 'w') as f:
        json.dump(schema, f, indent=4)  # pretty print JSON

def parse_sarif_file(filename):
    # Read and parse the JSON from a file
    with open(filename, 'r') as file:
        data = json.load(file)

    # Accessing some elements in the parsed JSON
    for run in data['runs']:
        print('Tool name:', run['tool']['driver']['name'])
        print('Semantic Version:', run['tool']['driver']['semanticVersion'])
        print()

        for result in run['results']:
            print('Fingerprints:', result['fingerprints']['matchBasedId/v1'])
            print('Location URI:', result['locations'][0]['physicalLocation']['artifactLocation']['uri'])
            print('Location Base_Id:', result['locations'][0]['physicalLocation']['artifactLocation']['uriBaseId'])
            print('Region End Column:', result['locations'][0]['physicalLocation']['region']['endColumn'])
            print('Region End Line:', result['locations'][0]['physicalLocation']['region']['endLine'])
            print('Start Column:', result['locations'][0]['physicalLocation']['region']['startColumn'])
            print('Start Column:', result['locations'][0]['physicalLocation']['region']['startLine'])
            # print('Name:', result['locations'][0]['physicalLocation']['region']['snippet']['text'])
            text = result['locations'][0]['physicalLocation']['region']['snippet']['text']
            packageName = text.split("\n")[0].strip()
            print('Name:', packageName)
            version = None
            match = re.search(r'"version":\s+"([^"]+)"', text)
            if match:
                version = match.group(1)
                print('Version:', version)
            else:
                print('Version not found in text')
            print('Message:', result['message']['text'])
            print('Properties:', result['properties']['exposure'])
            print('RuleId:', result['ruleId'])
            print()

            #Values froms the semgrep supply chain ci output
            fingerprint = result['fingerprints']['matchBasedId/v1']
            locationUri = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
            locationBaseId = result['locations'][0]['physicalLocation']['artifactLocation']['uriBaseId']

            #Regions and start columns are not used in this iteration
            regionEndColumn = result['locations'][0]['physicalLocation']['region']['endColumn']
            regionEndLine = result['locations'][0]['physicalLocation']['region']['endLine']
            startColumn = result['locations'][0]['physicalLocation']['region']['startColumn']
            startLine = result['locations'][0]['physicalLocation']['region']['startLine']
            message = result['message']['text']
            properties = result['properties']['exposure']
            ruleId = result['ruleId']

            description = result['message']['text']
            packageType = str(result['locations'][0]['physicalLocation']['artifactLocation']['uri'])
            modify_schema(locationUri, packageName, fingerprint, packageType, description, properties, ruleId, version)


# Ask the user for the file name
#filename = input("Please enter the file name: ")

# Use the function
#parse_sarif_file(filename)

# Create the parser and add argument
parser = argparse.ArgumentParser()
parser.add_argument("filename", help="The name of the file to be parsed")

# Parse the arguments
args = parser.parse_args()

# Use the function with the filename as an argument
parse_sarif_file(args.filename)


