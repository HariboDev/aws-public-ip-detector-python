from plyer import notification
from requests import get
import subprocess
import logging
import boto3
import yaml
import json
import os

logging.basicConfig(filename='Log.log', level=logging.INFO, format='%(asctime)s: %(levelname)s: %(message)s', datefmt='%d/%m/%y %H:%M:%S')
logging.FileHandler(filename='Log.log', mode='w', encoding='utf-8', delay=False)

def main():
    errors = 0
    try:
        with open(r'data.yml') as file:
            data = yaml.load(file, Loader=yaml.FullLoader)
        old_ip = data['Data']['LastKnownIp']
    except:
        logging.error("Unable to retrieve last known public IP (check permissions)")
        errors = errors + 1
    else:
        logging.info("Last known public IP: " + str(old_ip))

        try:
            ip = get('https://api.ipify.org').text
        except:
            logging.error("Unable to retrieve current public IP (check internet connection)")
            errors = errors + 1
        else:
            logging.info("Current public IP: " + str(ip))

            if old_ip != ip:
                logging.info("Change detected")
                results = changeDetected(old_ip, ip, data['Accounts'])
                errors = errors + results['errors']

                if errors == 0:
                    try:
                        data['Data']['LastKnownIp'] = ip
                        with open(r'data.yml', 'w') as file:
                            yaml.dump(data, file)
                    except:
                        logging.error("Unable to update last known public IP")
                        errors = errors + 1
                    else:
                        logging.info("Last known public IP updated successfully")
                        if results['changed']:
                            if data['Data']['Notifications']['Success']:
                                logging.info("Success notification delivered")
                                notification.notify(
                                    title='Public IP Detector',
                                    message='All security group ingress rules updated successfully',
                                    app_name='Public IP Detector',
                                    app_icon='wifi-logo.ico',
                                    timeout=5
                                )
                            else:
                                logging.info("No change notification skipped due to config")
                        else:
                            if data['Data']['Notifications']['NoRulesToUpdate']:
                                logging.info("No rules to update notification delivered")
                                notification.notify(
                                    title='Public IP Detector',
                                    message='Change detected but no related rules to update',
                                    app_name='Public IP Detector',
                                    app_icon='wifi-logo.ico',
                                    timeout=5
                                )
                            else:
                                logging.info("No rules to update notification skipped due to config")
                else:
                    logging.info("Purposely did not update last known public IP (fix errors and retry)")
                    if data['Data']['Notifications']['Failure']:
                        logging.info("Failure notification delivered")
                        notification.notify(
                            title='Public IP Detector',
                            message='Failed to update security group.\nView the log: ' + str(os.getcwd()) + '\Log.log',
                            app_name='Public IP Detector',
                            app_icon='wifi-logo.ico',
                            timeout=5
                        )
                    else:
                        logging.info("No change notification skipped due to config")
            else:
                logging.info("No change detected")
                if data['Data']['Notifications']['NoChange']:
                    logging.info("No change notification delivered")
                    notification.notify(
                        title='Public IP Detector',
                        message='No change detected',
                        app_name='Public IP Detector',
                        app_icon='wifi-logo.ico',
                        timeout=5
                    )
                else:
                    logging.info("No change notification skipped due to config")
    return errors

def changeDetected(old_ip, ip, data):
    errors = 0
    changed = False
    for account in data:
        logging.info("Checking account: " + str(account))
        try:
            client = boto3.client('ec2', aws_access_key_id=data[account]['Credentials']['AccessKey'], aws_secret_access_key=data[account]['Credentials']['Secret'])
            security_groups = client.describe_security_groups()
        except:
            logging.error("Failed to get security groups (check internet connection and IAM permissions - need 'ALLOW' for 'ec2:DescribeSecurityGroups' action)")
            errors = errors + 1
        else:
            logging.info("Security groups gathered successfully")
            for security_group_details in security_groups['SecurityGroups']:
                ec2 = boto3.resource('ec2', aws_access_key_id=data[account]['Credentials']['AccessKey'], aws_secret_access_key=data[account]['Credentials']['Secret'])
                security_group = ec2.SecurityGroup(security_group_details['GroupId'])
                logging.info("Checking security group: " + security_group_details['GroupId'])

                for ip_address in security_group_details['IpPermissions']:
                    for ip_range in ip_address['IpRanges']:
                        if ip_range['CidrIp'] == str(old_ip) + '/32':
                            if ip_address['IpProtocol'] == '-1':
                                try:
                                    remove_response = security_group.revoke_ingress(
                                                IpPermissions=[
                                                    ip_address
                                                ]
                                            )
                                    logging.debug(remove_response)
                                except Exception as e:
                                    logging.debug(e)
                                    logging.error("Failed to remove old security group rule (check internet connection and IAM permissions - need 'ALLOW' for 'ec2:RevokeSecurityGroupIngress' action)")
                                    errors = errors + 1
                                else:
                                    logging.info("Old security group rule removed successfully")

                                    try:
                                        add_response = security_group.authorize_ingress(
                                                    IpPermissions=[
                                                        {
                                                            'IpProtocol': ip_address['IpProtocol'],
                                                            'IpRanges': [
                                                                {
                                                                    'CidrIp': str(ip) + '/32'
                                                                },
                                                            ],
                                                            'UserIdGroupPairs': [
                                                                {
                                                                    'GroupId': security_group_details['GroupId']
                                                                },
                                                            ]
                                                        },
                                                    ]
                                                )
                                        logging.debug(add_response)
                                    except Exception as e:
                                        logging.debug(e)
                                        logging.error("Failed to create new security group rule (check internet connection and IAM permissions - need 'ALLOW' for 'ec2:AuthorizeSecurityGroupIngress' action)")
                                        errors = errors + 1
                                    else:
                                        logging.info("New security group rule created successfully")
                            else:
                                try:
                                    remove_response = security_group.revoke_ingress(
                                                IpPermissions=[
                                                    ip_address
                                                ]
                                            )
                                    logging.debug(remove_response)
                                except Exception as e:
                                    logging.debug(e)
                                    logging.error("Failed to remove old security group rule (check internet connection and IAM permissions - need 'ALLOW' for 'ec2:RevokeSecurityGroupIngress' action)")
                                    errors = errors + 1
                                else:
                                    logging.info("Old security group rule removed successfully")
                                    
                                    try:
                                        add_response = security_group.authorize_ingress(
                                                    IpPermissions=[
                                                        {
                                                            'IpProtocol': ip_address['IpProtocol'],
                                                            'FromPort': ip_address['FromPort'],
                                                            'ToPort': ip_address['ToPort'],
                                                            'IpRanges': [
                                                                {
                                                                    'CidrIp': str(ip) + '/32'
                                                                },
                                                            ],
                                                            'UserIdGroupPairs': [
                                                                {
                                                                    'GroupId': security_group_details['GroupId']
                                                                },
                                                            ]
                                                        },
                                                    ]
                                                )
                                        logging.debug(add_response)
                                    except Exception as e:
                                        logging.debug(e)
                                        logging.error("Failed to create new security group rule (check internet connection and IAM permissions - need 'ALLOW' for 'ec2:AuthorizeSecurityGroupIngress' action)")
                                        errors = errors + 1
                                    else:
                                        logging.info("New security group rule created successfully")
                            changed = True
                        else:
                            logging.info("Security group rule skipped (no match found)")
    
    return {'errors': errors, 'changed': changed}


if __name__ == '__main__':
    logging.info("Execution initiated...")
    errors = main()
    logging.info("Execution finished with " + str(errors) + " error(s)")
