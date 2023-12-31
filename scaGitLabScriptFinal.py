import json
import sys


def conversion_semgrep_to_gitlab(report_semgrep, data):
    print("Populating data from Semgrep JSON report")
    with open(report_semgrep, 'r') as file_semgrep:
        data_semgrep = json.load(file_semgrep)
        for vuln in data_semgrep['results']:
            new_vuln = {
                        "id": vuln.get('extra')['fingerprint'][0:63],
                        "name": "Semgrep: " + vuln['check_id'],
                        "description": vuln.get('extra')['message'],
                        "cve": vuln.get('extra').get('metadata')['sca-vuln-database-identifier'],
                        "severity": "Critical",
                        "solution": "Upgrade to version 2.8.2 or above", ## TODO: get all solutions 
                        "location": {
                            "file": vuln.get('extra').get('sca_info').get('dependency_match')['lockfile'],
                            "dependency": {
                            "package": {
                                "name": vuln.get('extra').get('sca_info').get('dependency_match').get('found_dependency')['package']
                            },
                            "version": vuln.get('extra').get('sca_info').get('dependency_match').get('found_dependency')['version']
                            }
                        },
                        "identifiers": [
                            {
                                "type": "cve",
                                "name": vuln.get('extra').get('metadata')['sca-vuln-database-identifier'],
                                "value": vuln.get('extra').get('metadata')['sca-vuln-database-identifier'],
                                "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name="+vuln.get('extra').get('metadata')['sca-vuln-database-identifier']
                            },
                            {
                                "type": "gemnasium",
                                "name":"Gemnasium-ef60b3d6-926c-472f-b24a-f585deccf8b6",
                                "value": "ef60b3d6-926c-472f-b24a-f585deccf8b6",
                                "url": "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/blob/master/maven/org.apache.logging.log4j/log4j-core/CVE-2017-5645.yml"
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
                            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name="+vuln.get('extra').get('metadata')['sca-vuln-database-identifier']
                            }
                        ],
                        "details": {
                            "vulnerable_package": {
                            "type": "text",
                            "name": "Vulnerable Package",
                            "value": vuln.get('extra').get('sca_info').get('dependency_match').get('found_dependency')['package'] 
                            + ":" + vuln.get('extra').get('sca_info').get('dependency_match').get('found_dependency')['version'] 
                        }
                    }
                        
            }
            data['vulnerabilities'].append(new_vuln)

        for vuln in data_semgrep['results']:
            new_file = { "path": vuln.get('extra').get('sca_info').get('dependency_match')['lockfile'],
                        "package_manager": vuln.get('extra').get('sca_info').get('dependency_match').get('dependency_pattern')['ecosystem'],
                        "dependencies": [
                            {
                            "package": {
                                "name": vuln.get('extra').get('sca_info').get('dependency_match').get('found_dependency')['package'] 
                            },
                            "version": vuln.get('extra').get('sca_info').get('dependency_match').get('found_dependency')['version'] 
                            }
                        ]
            }
            data['dependency_files'].append(new_file)

        new_scan_info = get_new_scan_info(data_semgrep)
        data['scan'] = new_scan_info

    print("Dumping to a GitLab JSON report")
    print(data)
    with open('gl-dependency-scanning-report.json', 'w') as f:
        json.dump(data, f, indent=4)  # pretty print JSON


def get_new_scan_info(data):
    new_scan_info = {
        "analyzer": {
        "id": "gemnasium-maven",
        "name": "semgrep",
        "url": "https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium",
        "vendor": {
            "name": "GitLab"
        },
        "version": data['version']
        },
        "scanner": {
        "id": "gemnasium-maven",
        "name": "semgrep",
        "url": "https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium",
        "vendor": {
            "name": "GitLab"
        },
        "version": data['version']
        },
        "type": "dependency_scanning",
        "start_time": "2023-07-20T14:54:46",
        "end_time": "2023-07-20T14:55:01",
        "status": "success"
    }
    return new_scan_info

def to_hungarian_case(input_string):
    hungarian_case_words = input_string[0].upper() + input_string[1:].lower()
    return hungarian_case_words



if __name__ == "__main__":

    if len(sys.argv) == 2:
        report_semgrep = sys.argv[1]
    print("Starting conversion process from Semgrep JSON to GitLab JSON")
    data = {
        "version": "15.0.0",
        "vulnerabilities": [],
        "dependency_files": [],
        "scan": {}
    }
    conversion_semgrep_to_gitlab(report_semgrep, data)
