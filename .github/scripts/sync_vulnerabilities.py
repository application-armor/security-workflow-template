import os
import requests
import json
import base64
import logging
from datetime import datetime
from time import sleep

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilitySync:
    def __init__(self):
        self.github_token = os.environ['GH_TOKEN']
        self.jira_base_url = os.environ['JIRA_BASE_URL']
        self.jira_api_token = os.environ['JIRA_API_TOKEN']
        self.jira_email = os.environ['JIRA_EMAIL']
        self.jira_epic_key = os.environ['JIRA_EPIC_KEY']
        
        # Setup auth headers for GitHub and Jira
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
        response = self._make_request(url, self.github_headers)
        
        if response is None:
            return []

        return response.json()

    def get_existing_jira_issues(self):
        """Get existing Jira issues under the epic"""
        jql = f'project = KAN AND "Epic Link" = {self.jira_epic_key}'
        url = f'{self.jira_base_url}/rest/api/3/search'
        response = self._make_request(url, self.jira_headers, params={'jql': jql, 'fields': 'summary,description,customfield_10015'})
        
        if response is None:
            return []

        return response.json().get('issues', [])

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

        response = self._make_request(url, self.jira_headers, method="POST", json=payload)
        
        if response:
            logger.info(f"Created Jira subtask: {response.json()['key']}")
        return response

    def is_duplicate(self, vulnerability, existing_issues):
        """Check if vulnerability already exists in Jira"""
        vuln_number = vulnerability['number']
        for issue in existing_issues:
            if issue['fields'].get('customfield_10015') == vuln_number:
                logger.info(f"Duplicate found: {vuln_number}")
                return True
        return False

    def _make_request(self, url, headers, method="GET", params=None, json=None):
        """Helper function to make requests and handle retries"""
        retries = 3
        for attempt in range(retries):
            try:
                response = requests.request(method, url, headers=headers, params=params, json=json)
                
                # Check for successful response
                if response.status_code == 200 or response.status_code == 201:
                    return response
                else:
                    logger.error(f"Error {response.status_code}: {response.text}")
                    return None
            except requests.exceptions.RequestException as e:
                logger.error(f"Error during request: {e}")
                sleep(2 ** attempt)  # Exponential backoff
        return None

    def sync_vulnerabilities(self):
        """Main sync function"""
        logger.info("Fetching vulnerabilities from GitHub...")
        vulnerabilities = self.get_github_vulnerabilities()
        
        logger.info("Fetching existing Jira issues...")
        existing_issues = self.get_existing_jira_issues()
        
        # Process each vulnerability
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):  # Ensure we have a valid dictionary before proceeding
                if not self.is_duplicate(vuln, existing_issues):
                    logger.info(f"Creating Jira subtask for vulnerability: {vuln['rule']['name']}")
                    self.create_jira_subtask(vuln)
            else:
                logger.warning(f"Skipping invalid vulnerability: {vuln}")

if __name__ == "__main__":
    syncer = VulnerabilitySync()
    syncer.sync_vulnerabilities()
