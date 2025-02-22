import os
import requests
import json
import base64
from datetime import datetime

class VulnerabilitySync:
    def __init__(self):
        self.github_token = os.environ['GH_TOKEN']
        self.jira_base_url = os.environ['JIRA_BASE_URL']
        self.jira_api_token = os.environ['JIRA_API_TOKEN']
        self.jira_email = os.environ['JIRA_EMAIL']
        self.jira_epic_key = os.environ['JIRA_EPIC_KEY']
        
        # Setup auth headers
        self.github_headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        self.jira_headers = {
            'Authorization': f'Basic {base64.b64encode(f"{self.jira_email}:{self.jira_api_token}".encode()).decode()}',
            'Content-Type': 'application/json'
        }

    def get_github_vulnerabilities(self):
        """Fetch vulnerabilities from GitHub Code Scanning API"""
        repo = os.environ['GITHUB_REPOSITORY']
        url = f'https://api.github.com/repos/{repo}/code-scanning/alerts'
        response = requests.get(url, headers=self.github_headers)
        return response.json()

    def get_existing_jira_issues(self):
        """Get existing Jira issues under the epic"""
        jql = f'project = KAN AND "Epic Link" = {self.jira_epic_key}'
        url = f'{self.jira_base_url}/rest/api/3/search'
        response = requests.get(
            url,
            headers=self.jira_headers,
            params={'jql': jql, 'fields': 'summary,description,customfield_10015'}
        )
        # Debugging the Jira response
        print(f"Jira API Response Status Code: {response.status_code}")
        print(f"Jira API Response Body: {response.text}")
        
        # If the response is successful, return issues
        if response.status_code == 200:
            return response.json().get('issues', [])
        else:
            raise ValueError(f"Failed to fetch Jira issues: {response.status_code} - {response.text}")

    def create_jira_subtask(self, vulnerability):
        """Create a Jira subtask for a vulnerability"""
        url = f'{self.jira_base_url}/rest/api/3/issue'
        
        description = f"""
        *Security Vulnerability Details*
        Rule: {vulnerability['rule']['name']}
        Severity: {vulnerability['rule']['severity']}
        Tool: {vulnerability['tool']['name']}
        Location: {vulnerability['most_recent']['location']['path']}:{vulnerability['most_recent']['location']['start_line']}
        
        *Description*
        {vulnerability['rule']['description']}
        
        *More Info*
        {vulnerability['html_url']}
        """

        payload = {
            "fields": {
                "project": {"key": "KAN"},
                "summary": f"Security: {vulnerability['rule']['name']}",
                "description": description,
                "issuetype": {"name": "Sub-task"},
                "parent": {"key": self.jira_epic_key},
                "customfield_10015": vulnerability['number']  # Store GitHub alert number
            }
        }

        response = requests.post(url, headers=self.jira_headers, json=payload)
        return response.json()

    def is_duplicate(self, vulnerability, existing_issues):
        """Check if vulnerability already exists in Jira"""
        # Debugging the structure of the vulnerability
        print(f"Checking vulnerability: {vulnerability}")
        
        if isinstance(vulnerability, dict):
            vuln_number = vulnerability.get('number', None)
            
            if not vuln_number:
                print("No vulnerability number found!")
                return False
            
            for issue in existing_issues:
                if issue['fields'].get('customfield_10015') == vuln_number:
                    return True
        else:
            print(f"Expected a dictionary, but got: {type(vulnerability)}")

        return False

    def sync_vulnerabilities(self):
        """Main sync function"""
        # Get vulnerabilities from GitHub
        vulnerabilities = self.get_github_vulnerabilities()
        
        # Debugging vulnerabilities response
        print(f"Fetched vulnerabilities: {json.dumps(vulnerabilities, indent=2)}")
        
        # Get existing Jira issues
        existing_issues = self.get_existing_jira_issues()
        
        # Process each vulnerability
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):  # Ensure the vulnerability is a dictionary
                if not self.is_duplicate(vuln, existing_issues):
                    self.create_jira_subtask(vuln)
            else:
                print(f"Skipping invalid vulnerability (not a dictionary): {vuln}")

if __name__ == "__main__":
    syncer = VulnerabilitySync()
    syncer.sync_vulnerabilities()
