import requests

API_KEY = 'Your_Api_Key'

def scan_file(file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    params = {'apikey': API_KEY}
    files = {'file': file_data}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    response_json = response.json()
    if response.status_code == 200:
        resource_url = response_json.get('resource')
        return resource_url
    else:
        raise Exception('Scan failed with error code: ' + str(response.status_code))

def check_report(resource_url):
    params = {'apikey': API_KEY, 'resource': resource_url}
    headers = {'Accept-Encoding': 'gzip, deflate', 'User-Agent': 'gzip,  My Python requests library example client or username'}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    response_json = response.json()
    if response.status_code == 200:
        return response_json
    else:
        raise Exception('Report check failed with error code: ' + str(response.status_code))

if __name__ == '__main__':
    file_path = input("Enter the file path to scan: ")
    resource_url = scan_file(file_path)
    report = None
    while report is None:
        report = check_report(resource_url)
        if report.get('response_code') == 0:
            raise Exception('File not found in VirusTotal database')
    positives = report.get('positives')
    total = report.get('total')
    print(f'{positives}/{total} scanners detected malware in this file')
