# Public IP Detector

Python script to periodically and automatically detect a change in your public IP address. If so, all AWS EC2 security groups containing your old public IP will be updated to use your new IP. This tool uses Python and the Boto3 python SDK for AWS.

## Overview

- When executed, this tool will check to see if your public IP address is the same as last time.
    - If it is the same, the tool will exit.
    - If it has changed, it will:
        - Remove the ingress rule for your old public IP address.
        - Add a new ingress rule for your new public IP address using the same protocols and ports as the old rule.

## Prerequisites

This application requires the following items to be installed prior to running the installer:
- Python 3 (with user or system environment variable)
- Pip (with user or system environment variable)

The IAM users will also need to have the following permissions allowed on each of the accounts they want checking:
- `ec2:DescribeSecurityGroups`
- `ec2:RevokeSecurityGroupIngress`
- `ec2:AuthorizeSecurityGroupIngress`

## Installation

- Run the following command using the command prompt:
    ```
    pip install boto3 requests pyyaml plyer
    ```
- Clone the repository:
    ```
    git clone https://github.com/hlacannon/aws-public-ip-detector.git
    ```
- If you want the tool to run automatically at a given frequency, run the following command:
    ```
    SCHTASKS /CREATE /SC Variable1 /MO Variable2 /TN hlacannon\aws-public-ip-detector /TR Variable3\schedule.bat
    ```
    Where:
    - Variable1 is the frequency intenger (i.e. 1, 7, etc.)
    - Variable2 is the frequency type (i.e. MINUTE, HOURLY, DAILY, etc.)
    - Variable3 is the path where you cloned the repository 

    For more information on the Windows Task Scheduler, visit https://docs.microsoft.com/en-us/windows/win32/taskschd/using-the-task-scheduler

## Post-Installation

Before this tool is able to run successfully, you will need to provide the programmatic access keys (access keys and secrets) for your different AWS accounts (e.g. Personal, Work, etc.).

These are required as the tool uses the AWS SDK boto3. The programmatic access keys will need to be stored in the `data.yml` file in the following format:

```
# data.yml

Accounts:
    Personal:
        Credentials:
            AccessKey: your-access-key-here
            Secret: your-secret-here
    Work:
        Credentials:
            AccessKey: your-access-key-here
            Secret: your-secret-here
Data:
    LastKnownIp: your-current-public-ip-address
    Notifications:
        Failure: true
        NoChange: true
        NoRulesToUpdate: true
        Success: true
```
*\* The account names can be customised and more can be added*

## Execution

- If you have set up the Windows Task Scheduler task correctly, the tool should run at the frequency you specified.
- If you haven't set up the Windows Task Scheduler task or would like to run the program directly:
    - In the command line navigate to the repository folder and run:
        ```
        python public_ip_detector.py
        ```
    - Or execute the run.vbs file.

## Custom Configuration

Within the `data.yml` file you will notice 4 different notifications (Failure, NoChange, NoRulesToUpdate & Success). The boolean values of these attributes can be customised and will be used to determine whether to notify you of the following:
- Failure:
    - Used to determine whether you should be notified when the tool fails to execute completely and further detail will be recorded in the log (`Log.log`)
    - Default value: `true`
- NoChange:
    - Used to determine whether you should be notified when the tool doesn't recognise a change in your public IP since last time
    - Default value: `true`
- NoRulesToUpdate:
    - Used to determine whether you should be notified when the tool recognises a change in your public IP but can't find any security group ingress rules associated to your old public IP
    - Default value: `true`
- Success:
    - Used to determine whether you should be notified when the tool recognises a change in your public IP and successfully updates all security group ingress rules associated to your IP
    - Default value: `true`

## Debugging

The results of the AWS API calls are logged each time the tool is executed and are available to view at `your-installation-path\Log.log`.

If you need help debugging or find a bug, please [raise an issue](https://github.com/hlacannon/aws-public-ip-detector/issues/new).

## Contributing

Contributions are welcomed and appreciated. If you have an idea for a new feature, or find a bug, you can [open an issue](https://github.com/hlacannon/aws-public-ip-detector/issues/new) and report it. Or if you are in the devloping mood, you can fork this repository, implement the idea or fix the bug and [submit a new pull request](https://github.com/hlacannon/aws-public-ip-detector/compare).
