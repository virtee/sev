# SPDX-License-Identifier: Apache-2.0

'''
Triggers PR CI test workflows on all the open PRs for the given GH owner, GH repository and GH Workflow ID
This script is used as an event after SNP kernel update on the self-hosted runner

Pre-requisite for this tool use:
     Set DOTENV_PATH(environment variable) on the host with the .env file path having VIRTEE_API_TOKEN
'''

import requests
import time
from dotenv import load_dotenv
import os

def trigger_open_pr_tests(owner, repo, workflow_id):
    '''
        Activates GH Workflow for the given GH owner, GH repo and GH Action workflow ID
    '''
    # Loads Virtee Repository PAT for GH Action API use to trigger GH workflow
    dotenv_path = os.path.join(os.path.dirname(__file__), os.getenv("DOTENV_PATH"))
    load_dotenv(dotenv_path)
    virtee_api_token = os.getenv("VIRTEE_API_TOKEN")

    # Constructs the API URL
    workflow_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"

    # Sets header with authorization and API version
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {virtee_api_token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    open_pr_url = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open"
    headers = {"Authorization": f"token {virtee_api_token}"}

    # Gets all open PR list for the given GH owner, GH repo and GH workflow ID
    all_open_prs = requests.get(open_pr_url, headers=headers)

    # Activate Virtee CI PR test workflow for all open PRs via GH Action API
    if all_open_prs.status_code == 200:
        prs = all_open_prs.json()
        for pr in prs:

            pr_number =  pr['html_url'].split("pull/")[-1]
            pr_source_branch =  pr['head']['ref']
            pr_inputs = {"pull_request_number": pr_number,"pull_request_branch":pr_source_branch }

            # Prepares the data payload with branch name and inputs
            pr_post_data = {
                "ref": "main",
                "inputs": pr_inputs
            }

            print(f"\nTriggers {repo} PR CI test for PR #{pr_number} and PR source branch {pr_source_branch}")
            pr_ci_test = requests.post(workflow_url, headers=headers, json=pr_post_data)

            # Handles the response
            if pr_ci_test.status_code != 204:
                print(f"ERROR: {pr_ci_test.status_code}" + " - " + f"{repo} PR CI test workflow request fails for PR #{pr_number}(PR source branch:{pr_source_branch})")
                print(f"ERROR CAUSE: {pr_ci_test.json()}")
    else:
        print(f"\n ERROR: {all_open_prs.status_code}" + " - " + f"GET request to all the {repo} open PRs list fails!")
        print(f"ERROR CAUSE: {all_open_prs.json()}")
        print(f"\n")

def main():
    # Initializes Virtee Repositories list
    virtee_owner = "virtee"

    virtee_repo_workflows= {
                            "sev":"sev_ci_pr_test.yaml",
                            "snphost":"snphost_ci_test.yaml",
                            "snpguest":"snpguest_ci_pr_test.yaml"
                           }

    # Trigger all open PR CI tests for all Virtee Repositories
    for repo, workflow in virtee_repo_workflows.items():
        trigger_open_pr_tests(virtee_owner, repo, workflow)

if __name__ == '__main__':
    main()

