import CX1_api
from CX1_api import Email_from, Email_subject 
import sys

#################################################
# main code
######<###########################################
def main():

    if(len(sys.argv) < 3):
        print('usage: Create_cx1_alert <notification email> <interval>')
        exit()
    
    email_recipients = sys.argv[1]  
    interval = sys.argv[2]  
    print('email_recipients: ' + email_recipients)
    print('interval: ' + str(interval) )

    project_list = CX1_api.get_projects()

    for project in project_list:
        project_name = project['name']
        project_id = project['id']

        high_count, medium_count = CX1_api.get_sca_results(project_name, project_id, interval)

        print(str(high_count) + ' high vulnrabilities')
        print(str(medium_count) + ' medium vulnrabilities')

        if(high_count > 0 or medium_count > 0):
            # Set email variables
            email_from = Email_from
            email_subject = Email_subject
            email_body = (
                f"Project: {project_name}\n"
                f"{high_count} high vulnerabilities\n"
                f"{medium_count} medium vulnerabilities\n"
                )
    
            # Send email
            CX1_api.send_email(email_from, email_recipients, email_subject, email_body)

 
if __name__ == '__main__':
   main()