import requests
import json
import yaml
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText

# Open the YAML file
with open('config_cx1.yaml', 'r') as file:
    # Load the YAML contents
    config = yaml.safe_load(file)

CX1_tenant = config['CX1_tenant']
CX1_clientid = config['CX1_clientid']
CX1_secret = config['CX1_secret']
CX1_api_url = config['CX1_api_url']
CX1_proxy = config['CX1_proxy']
proxy_servers = {
   'https': CX1_proxy
}
SMTP_server = config['SMTP_server']
SMTP_port = config['SMTP_port']
SMTP_tls = config['SMTP_tls']
SMTP_user = config['SMTP_user']
SMTP_password = config['SMTP_password']
Email_from = config['Email_from']
Email_subject = config['Email_subject']

# Function to send email
def send_email(sender, email_recipients, subject, body):
    recipients_list = email_recipients.split(',')  # Split the email_recipients string into individual email addresses
    recipients = [recipient.strip() for recipient in recipients_list]  # Remove leading/trailing spaces

    message = MIMEText(body)
    message['From'] = sender
    message['To'] = ", ".join(recipients)  # Join recipients list into a comma-separated string
    message['Subject'] = Email_subject

    try:
        smtp_obj = smtplib.SMTP(SMTP_server, SMTP_port)  
        if(SMTP_tls):
            smtp_obj.starttls()

        if(SMTP_user and SMTP_password):
            smtp_obj.login(SMTP_user, SMTP_password)  
        smtp_obj.sendmail(sender, recipients, message.as_string())  # Send email to all recipients
         
        smtp_obj.quit()
    except Exception as e:
        print("Exception: Failed to send email:", str(e))

def get_access_token():
    try:

        # Define the URL and headers
        url = f'https://eu.iam.checkmarx.net/auth/realms/{CX1_tenant}/protocol/openid-connect/token'

        # Define the payload
        payload = {
            'client_id': CX1_clientid,
            'grant_type': 'client_credentials',
            'client_secret': CX1_secret
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        # Make the POST request
        response = requests.post(url, headers=headers, data=payload, verify=False, proxies=proxy_servers)

#        print('get_CX1_access_token - token = ' + response.text)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        access_token = response.json()['access_token']
        return access_token
    except requests.RequestException as e:
        print("Exception: Failed to get access token:", str(e))
        return ""

def get_project_latest_scan_id(access_token, project_name, project_id):

    if(not project_id):
        project_id = get_project_id(access_token, project_name)
    
    if(project_id):
        url = CX1_api_url + "/projects/last-scan?project-ids=" + project_id

        try:
            payload = {}
            headers = {
            'Authorization': 'Bearer ' + access_token
            }

            response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
            response_json = response.json()
        except Exception as e:
            print("Exception: get_project_latest_scan_id:", str(e))
            return ""
        else:
            print('get_project_latest_scan_id scan_id= ' + response_json[project_id]['id'])
            created_at_str = response_json[project_id]['createdAt']
            # Convert createdAt string to datetime object
            created_at = datetime.strptime(created_at_str, "%Y-%m-%dT%H:%M:%S.%fZ")

            return response_json[project_id]['id'], created_at
    else:
        return ""        

def create_project(access_token, project_name, api_url, proxy_servers=None):
    url = CX1_api_url + "/api/projects"

    try:
        payload = json.dumps({
        "Name": project_name
        })
        headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("POST", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        project_id = response_json['id']  # Assuming the first project with the given name is returned
    except Exception as e:
        print("Exception: create_project:", str(e))
        return ""
    else:
        print('create_project - project_name= ' + response.text)
        return project_id

def get_projects(access_token=""):

    if(not access_token):
        access_token = get_access_token()

    url = f"{CX1_api_url}/projects"

    try:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()

    except requests.RequestException as e:
        print("Exception: Failed to get projects:", str(e))
        return ""
    else:
        return response_json["projects"]
    
def get_project_id(access_token, project_name):
    url = f"{CX1_api_url}/projects"

    try:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()

        # find id corresponding to name
        project_id = None

        # Iterate through the projects list to find the matching project name
        for project in response_json["projects"]:
            if project["name"] == project_name:
                project_id = project["id"]
                break

    except requests.RequestException as e:
        print("Exception: Failed to get project ID:", str(e))
        return ""
    except (KeyError, IndexError):
        print("Exception: Project ID not found")
        return ""
    else:
        print('get_project_id id:', project_id)
        return project_id

def get_upload_link(access_token, project_id, api_url, proxy_servers=None):
    url = f"{CX1_api_url}/api/uploads"

    try:
        payload = {
            "projectId": project_id
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.post(url, headers=headers, json=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        upload_url = response_json.get('url')
    except requests.RequestException as e:
        print("Exception: Failed to get upload link:", str(e))
        return ""
    except KeyError:
        print("Exception: 'uploadUrl' key not found in response")
        return ""
    else:
        print('get_upload_link - uploadUrl:', upload_url)
        return upload_url

def upload_file(access_token, upload_link, zip_file_path, proxy_servers=None):
    try:
        with open(zip_file_path, 'rb') as file:
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-zip-compressed',
                'Authorization': 'Bearer ' + access_token
            }
            response = requests.put(upload_link, headers=headers, data=file, proxies=proxy_servers, verify=False)
            response.raise_for_status()  # Raise an error for bad responses
            print('upload_file:', response.text)
    except requests.RequestException as e:
        print("Exception: Failed to upload file:", str(e))

def scan_zip(access_token, project_id, upload_file_url, api_url, proxy_servers=None):
    url = f"{CX1_api_url}/api/scans/uploaded-zip"

    try:
        payload = {
            "projectId": project_id,
            "uploadedFileUrl": upload_file_url
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.post(url, headers=headers, json=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        print('SCA_scan_zip scan_id:', response_json['scanId'])
        return response_json['scanId']
    except requests.RequestException as e:
        print("Exception: Failed to initiate scan:", str(e))
        return None
    except KeyError:
        print("Exception: 'scanId' key not found in response")
        return None

def get_scan_status(access_token, scan_id, CX1_api_url, proxy_servers=None):
    url = CX1_api_url + "/api/scans/" + scan_id
    
    try:
        payload = {}
        headers = {
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        status = response.content
   
    except Exception as e:
        print("Exception: get_scan_status", str(e))
        return ""
    else:
        print('get_scan_status')
        return status

def get_sca_results(project_name, project_id, interval_minutes = ""):
    access_token = get_access_token()
    if access_token:
        scan_id, created_at = get_project_latest_scan_id(access_token, project_name, project_id)

        if(scan_id):
            if(interval_minutes):

                # Get the current time
                current_time = datetime.utcnow()
                # Define an interval in minutes
                interval = timedelta(minutes=int(interval_minutes))

                # Calculate the time range
                start_time = current_time - interval
                end_time = current_time

                # Compare the dates
                if start_time < created_at < end_time:

                    url = CX1_api_url + "/scan-summary?scan-ids=" + scan_id 
    
                    try:
                        payload = {}
                        headers = {
                        'Authorization': 'Bearer ' + access_token
                        }

                        response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
                        response.raise_for_status()  # Raise an error for bad responses
                        response_json = response.json()
                    except Exception as e:
                        print("Exception: get_report", str(e))
                        return ""
                    else:
                        counters = response_json['scansSummaries'][0]['scaCounters']
                        high_counter = response_json['scansSummaries'][0]['scaCounters']['severityCounters'][1]['counter']
                        medium_counter = response_json['scansSummaries'][0]['scaCounters']['severityCounters'][0]['counter']
                        return high_counter, medium_counter
                else:
                    return 0, 0 

def report_get_vulnerabilities_count_from_json(file_path):
    try:
        # Load JSON data from the file with explicit encoding
        with open(file_path, encoding='utf-8') as file:
            json_data = json.load(file)

        high_vulnerability_count = json_data['RiskReportSummary']['HighVulnerabilityCount']
        medium_vulnerability_count = json_data['RiskReportSummary']['MediumVulnerabilityCount']

    except Exception as e:
        print("Exception: report_get_high_vulnerabilities_count failed:", str(e))
        return 0
    else:
        return high_vulnerability_count, medium_vulnerability_count

def scan_packages(project_name, zip_manifest_file, auth_url, CX1_api_url, proxy_servers=None):
    access_token = get_access_token()
    if access_token:
        project_id = get_project_id(access_token, project_name)
        if (project_id == ''):
            project_id = create_project(access_token, project_name)
            if project_id:
                upload_file_url = get_upload_link(access_token, project_id)
                if upload_file_url:
                    upload_file(access_token, upload_file_url, zip_manifest_file)
                    scan_id = scan_zip(access_token, project_id)
                return scan_id
    return None
