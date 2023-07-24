import json
import argparse
import re

class gitlab_security_report_schemas:
    def __init__(self, dependency_vulnerability_schema, analyzer_schema, dependency_scanning_report_schema):
        self.dependency_vulnerability = dependency_vulnerability_schema
        self.analyzer = analyzer_schema
        self.dependency_scanning_report = dependency_scanning_report_schema

class gitlab_dependency_vulnerability_v15:
     def __init__(self, id, vulnerability_name, description, severity, solution, dependency_files, dependency_name, dependency_version):
        self.id = id
        self.name = vulnerability_name
        self.description = description
        self.cve = ""
        self.severity = severity
        self.solution = solution
        self.location = {
            "dependency_files": dependency_files,
            "dependency": {
                "package": {
                    "name": dependency_name
                }
            },
            "version": dependency_version
        }

class gitlab_analyzer_v15:
    def __init__(self, id, analyzer_name, vendor_name, url, version):
        self.id = id
        self.name = analyzer_name
        self.url = url
        self.vendor = {
            "name": vendor_name
        }
        self.version = version

class gitlab_dependency_report_v15:
    def __init__(self, analyzer, dependency_vulnerability_list, start_time, end_time, scan_status):
        self.version = "15.0.0"
        self.vulnerabilities = dependency_vulnerability_list
        self.scan = {
            "analyzer": analyzer,
            "type": "dependency_scanning",
            "start_time": start_time,
            "end_time": end_time,
            "status": scan_status
        }

GITLAB_SECURITY_REPORTING_V15 = gitlab_security_report_schemas(gitlab_dependency_vulnerability_v15, gitlab_analyzer_v15, gitlab_dependency_report_v15)

def parse_sarif_file(filename):
    # Read and parse the JSON from a file
    data = {}
    with open(filename, 'r') as file:
        data = json.load(file)
    return data

def log_semgrep_dependency_scan_data(scan_data):
    for run in scan_data['runs']:
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


def convert_semgrep_sarif_to_gitlab_security_report_schema(semgrep_sarif, gitlab_report_schema):
    analyzer = gitlab_report_schema.analyzer("gemnasium_maven", "Semgrep", "GitLab", "https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium", "4.1.0");
    vulnerability_list = []
    for run in semgrep_sarif['runs']:
        for result in run['results']:
            text = result['locations'][0]['physicalLocation']['region']['snippet']['text']
            packageName = text.split("\n")[0].strip().replace('\"', '').replace(':', '').replace(' ', '').replace('{', '')
            version = None
            match = re.search(r'"version":\s+"([^"]+)"', text)
            if match:
                version = match.group(1)
                print('Version:', version)

            #Values froms the semgrep supply chain ci output
            locationBaseId = result['locations'][0]['physicalLocation']['artifactLocation']['uriBaseId']

            #Regions and start columns are not used in this iteration
            properties = result['properties']['exposure']
            severity = 'Critical' if (properties == 'reachable') else 'High'
            packageType = str(result['locations'][0]['physicalLocation']['artifactLocation']['uri'])

            vulnerability = gitlab_report_schema.dependency_vulnerability(
                id=result['fingerprints']['matchBasedId/v1'],
                vulnerability_name=packageName,
                description=result['message']['text'],
                severity=severity,
                solution="Please review Semgrep SCA rule" + result['ruleId'],
                dependency_files=result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                dependency_name=result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                dependency_version=version)

            vulnerability_list.Append(vulnerability)

    return gitlab_report_schema.dependency_scanning_report(
        analyzer=analyzer,
        dependency_vulnerability_list=vulnerability_list,
        start_time="2023-07-20T14:54:46",
        end_time="2023-07-20T14:55:01",
        scan_status="success"
    )

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
parsed_file = parse_sarif_file(args.filename)

log_semgrep_dependency_scan_data(parsed_file)

schema = convert_semgrep_sarif_to_gitlab_security_report_schema(parsed_file, GITLAB_SECURITY_REPORTING_V15)

# Save the modified schema to a file
with open('gl-dependency-scanning-report.json', 'w') as f:
    json.dump(schema, f, indent=4)  # pretty print JSON