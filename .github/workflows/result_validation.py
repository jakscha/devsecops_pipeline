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
        data = self.load_json_from_file('report_json.json')

        for result in data['site']:
            for finding in result['alerts']:
                if 'High' in finding['riskdesc'] or 'Critical' in finding['riskdesc']:
                    self.count += 1
                    valid = False
        return valid

    def validate_nuclei(self):
        valid = True
        data = self.load_json_from_file('nuclei.sarif')

        for run in data['runs']:
            for result in run['results']:
                if result['level'] == 'critical' or result['level'] == 'high':
                    self.count += 1
                    valid = False
        return valid

    def validate_snyk(self):
        valid = True
        data = self.load_json_from_file('snyk.json')
        return valid


    def validate_trivy(self):
        valid = True
        data = self.load_json_from_file('trivy.json')
        findings = data['Results']

        for result in data['Results']:
            for finding in result['Vulnerabilities']:
                if finding['Severity'] == 'HIGH' or finding['Severity'] == 'CRITICAL':
                    self.count += 1
                    valid = False
        return valid

    def validate_bearer(self):
        valid = True
        data = self.load_json_from_file('bearer.json')
        if 'high' in data:
            self.count += len(data['high'])
            valid = False
        if 'critical' in data:
            self.count += len(data['critical'])
            valid = False
        return valid

    def scan(self):
        tools = ''
        valid = True
        if not self.validate_bearer():
            tools += 'Bearer'
            valid = False
            print(f'Bearer scan did not pass.')
        else:
            print(f'Bearer scan passed.')
        if not self.validate_nuclei():
            tools += 'Nuclei '
            valid = False
            print(f'Nuclei scan did not pass.')
        else:
            print(f'Nuclei scan passed.')
        if not self.validate_zap():
            tools += 'Zap '
            valid = False
            print(f'Zap scan did not pass.')
        else:
            print(f'Zap scan passed.')
        if not self.validate_snyk():
            tools += 'Snyk '
            valid = False
            print(f'Snyk scan did not pass.')
        else:
            print(f'Snyk scan passed.')
        if not self.validate_trivy():
            tools += 'Trivy '
            valid = False
            print(f'Trivy scan did not pass.')
        else:
            print(f'Trivy scan passed.')


        tools = tools.replace(' ', ', ')[:-2]
        scan_result = f'There were {self.count} high/critical severity vulnerabilities found by: {tools}'

        with open(os.getenv('GITHUB_ENV'), 'a') as env_file:
            env_file.write(f'SCAN_VALID={valid}\n')

        with open(os.getenv('GITHUB_ENV'), 'a') as env_file:
            env_file.write(f'SCAN_RESULT={scan_result}\n')


try:
    ResultValidation().scan()
except Exception as e:
    print(e)
