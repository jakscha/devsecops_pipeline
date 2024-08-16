import json
import os


class ResultValidation:
    def load_json_from_file(self, file_name: str) -> dict:
        with open(f'.github/workflows/results/{file_name}', "r") as f:
            return json.load(f)

    def set_env_variable(self):
        with open(os.getenv('GITHUB_ENV'), 'a') as env_file:
            env_file.write('SCAN_VALID=true\n')
    def validate_zap(self):
        pass

    def validate_nuclei(self):
        pass

    def validate_trivy(self):
        data = self.load_json_from_file('trivy.json')
        findings = data['Results']
        print(type(findings))
        for result in data['Results']:
            for finding in result['Vulnerabilities']:
                if finding['Severity'] == 'HIGH' or finding['Severity'] == 'CRITICAL':
                    pass

    def validate_bearer(self):
        pass


val = ResultValidation()
val.validate_trivy()
val.set_env_variable()
