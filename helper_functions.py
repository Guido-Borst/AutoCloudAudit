# Copyright (c) 2024 Guido Borst
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import re
import os
import json
import analyze

###### 1. Extracting check ids from prowler_all_aws_checks.txt
def load_check_ids():
    check_ids = []
    with open('prowler_all_aws_checks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            check_ids.append(line)
    return check_ids

# ids = load_check_ids()
# with open('checks_mappings.txt', 'r') as file:
#         for line in file:
#             line = line.strip()
#             if line.startswith('- '):
#                 check_id = line[2:].strip()
#                 if check_id not in ids:
#                     print(check_id + ' not found in prowler_all_aws_checks.txt')
#                 else:
#                     ids.remove(check_id)
#         if ids:
#             print('The following check ids were not found in checks_mappings.txt:')
#             for check_id in ids:
#                 print(check_id)

###### 1. Extracting check ids from scoutsuite_all_aws_checks.txt
def load_check_ids():
    check_ids = []
    with open('scoutsuite_all_aws_checks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            check_ids.append(line)
    return check_ids

# ids = load_check_ids()
# with open('checks_mappings.txt', 'r') as file:
#         for line in file:
#             line = line.strip()
#             if line.startswith('+ '):
#                 check_id = line[2:].strip()
#                 if check_id not in ids:
#                     print(check_id + ' not found in scoutsuite_all_aws_checks.txt')
#                 else:
#                     ids.remove(check_id)
#         if ids:
#             print(f'The following {len(ids)} check ids were not found in checks_mappings.txt:')
#             for check_id in ids:
#                 print(check_id)




###### ScoutSuite checks 
def extract_info_from_json_rules():
    directory = 'tools/temptools/ScoutSuite/ScoutSuite/providers/aws/rules/findings/'
    info_list = []
    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            with open(os.path.join(directory, filename), 'r') as file:
                data = json.load(file)
                description = data.get('description', '')
                rationale = data.get('rationale', '')
                info_list.append(f'[{os.path.splitext(filename)[0]}] {description} -- {rationale}')
    info_list.sort()
    for i in range(0, len(info_list), 8):
        print('\n'.join(info_list[i:i+8]), end='\n\n\n')

# extract_info_from_json_rules()

def extract_scoutsuite_check_names():
    directory = 'tools/temptools/ScoutSuite/ScoutSuite/providers/aws/rules/findings/'
    info_list = []
    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            with open(os.path.join(directory, filename), 'r') as file:
                info_list.append(f'{os.path.splitext(filename)[0]}')
    info_list.sort()
    # write to file scoutsuite_all_aws_checks.txt
    with open('scoutsuite_all_aws_checks.txt', 'w') as file:
        for item in info_list:
            file.write(item + '\n')
# extract_scoutsuite_check_names()





def print_cloudsploit_checks_info(filter_top10=False, filter_high_severity=False):
    info_list = analyze.extract_cloudsploit_aws_check_details()

    # # Save info_list to a JSON file
    # with open('cloudsploit_checks_info.json', 'w') as file:
    #     json.dump(info_list, file)

    if filter_top10:
        services = ['ec2', 's3', 'lambda', 'rds', 'cloudfront', 'vpc', 'sns', 'elasticbeanstalk', 'autoscaling', 'iam']
        filtered_info_list = [info for info in info_list if info['service'] in services]
        info_list = filtered_info_list

    if filter_high_severity:
        severities = ['Critical', 'High']
        filtered_info_list = [info for info in info_list if info['severity'] in severities]
        info_list = filtered_info_list
    # for info in info_list:
        # print(f"Service: {info['service']}\nCheckname: {info['checkname']}\nTitle: {info['title']}\nSeverity: {info['severity']}\nDescription: {info['description']}\nMore Info: {info['more_info']}\n\n")

    # print check in format: [title] description -- more_info
    print(f'Total checks: {len(info_list)}')
    for i in range(0, len(info_list), 8):
        for info in info_list[i:i+8]:
            print(f"[{info['title']}] {info['description']} -- {info['more_info']}")
        print('\n\n')
    print(f'Total checks: {len(info_list)}')
    
# print_cloudsploit_checks_info(filter_top10=False, filter_high_severity=True)


def save_cloudsploit_check_names():
    info_list = analyze.extract_cloudsploit_aws_check_details()
    print(f'Total checks: {len(info_list)}')
    check_name_title = [(info['checkname'], info['title']) for info in info_list]
    # sort by checkname
    check_name_title.sort(key=lambda x: x[0])

    with open('cloudsploit_all_aws_checks.txt', 'w') as file:
        for check_name, title in check_name_title:
            file.write(f'{title}\n')
            # file.write(f'{title} - {check_name}\n')
# save_cloudsploit_check_names()

def print_all_categories():
    info_list = analyze.extract_cloudsploit_aws_check_details()
    categories = set()
    severities = set()
    for info in info_list:
        categories.add(info['service'])
        severities.add(info['severity'])
    print(sorted(categories))
    print(severities)
    
    for severity in severities:
        count = sum(1 for info in info_list if info['severity'] == severity)
        print(f"Number of items for severity {severity}: {count}")

    # filter on ec2, s3, lambda, rds, cloudfront, vpc, sns, elasticbeamstalk, autoscaling, iam
    # print number of checks for each filtered service
    services = ['ec2', 's3', 'lambda', 'rds', 'cloudfront', 'vpc', 'sns', 'elasticbeanstalk', 'autoscaling', 'iam']
    for service in services:
        count = sum(1 for info in info_list if info['service'] == service)
        print(f"Number of items for service {service}: {count}")

# print_all_categories()
