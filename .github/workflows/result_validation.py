import json


class ResultValidation:
    def load_json_from_file(self, file_name: str) -> dict:
        with open(f'.github/workflows/results/{file_name}', "r") as f:
            return json.load(f)

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
                    raise Exception('Critical or high vulnerability was found.')

    def validate_bearer(self):
        pass


ResultValidation().validate_trivy()
