import json
import os


class ResultValidation:

    def __init__(self):
        self.count = 0

    def load_json_from_file(self, file_name: str) -> dict:
        with open(f'.github/workflows/results/{file_name}', "r") as f:
            return json.load(f)

    def validate_zap(self):
        valid = True
        data = self.load_json_from_file('zap_scan/report_json.json')
        findings = data['Results']
        print(type(findings))
        for result in data['site']:
            for finding in result['alerts']:
                if 'High' in finding['riskdesc'] or 'Critical' in finding['Severity']:
                    self.count += 1
                    valid = False
        return valid

    def validate_nuclei(self):
        return True

    def validate_trivy(self):
        valid = True
        data = self.load_json_from_file('trivy.json')
        findings = data['Results']
        print(type(findings))
        for result in data['Results']:
            for finding in result['Vulnerabilities']:
                if finding['Severity'] == 'HIGH' or finding['Severity'] == 'CRITICAL':
                    self.count += 1
                    valid = False
        return valid

    def validate_bearer(self):
        return True

    def scan(self):
        tools = ''
        valid = True
        if not self.validate_zap():
            tools += 'Zap '
            valid = False
            print(f'Zap scan: {valid}')
        if not self.validate_nuclei():
            tools += 'Nuclei '
            valid = False
            print(f'Nuclei scan: {valid}')
        if not self.validate_trivy():
            tools += 'Trivy '
            valid = False
            print(f'Trivy scan: {valid}')
        if not self.validate_bearer():
            tools += 'Bearer'
            valid = False
            print(f'Bearer scan: {valid}')

        tools = tools.replace(' ', ', ')[:2]
        scan_result = f'There were {self.count} high/critical severity vulnerabilities found by: {tools}'

        with open(os.getenv('GITHUB_ENV'), 'a') as env_file:
            env_file.write(f'SCAN_VALID={valid}\n')

        with open(os.getenv('GITHUB_ENV'), 'a') as env_file:
            env_file.write(f'SCAN_RESULT={scan_result}\n')


try:
    ResultValidation().scan()
except Exception as e:
    print(e)
