# Copyright (c) 2024 Guido Borst
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import pandas as pd
import json
import glob
from prettytable import PrettyTable
from termcolor import colored
import os
import re
import selectionmenu

# Colors for the terminal
GREEN = '\033[92m'
YELLOW = '\033[93m'
ORANGE = '\033[38;5;208m'
RED = '\033[91m'
BOLD = '\033[1m'
NC = '\033[0m'



def print_dict_structure(d, indent=0, max_depth=2):
    if indent > max_depth:
        return
    for key, value in d.items():
        if isinstance(value, dict):
            print('  ' * indent + str(key), '(' + str(type(value).__name__) + ', ' + str(len(value.keys())) + ')')
            print_dict_structure(value, indent+1, max_depth)
        elif isinstance(value, list):
            print('  ' * indent + str(key), '(' + str(type(value).__name__) + ', length: ' + str(len(value)) + ')', end='')
            if value and isinstance(value[0], dict):
                print_dict_structure(value[0], indent+1, max_depth)
            else:
                print()
        else:
            print('  ' * indent + str(key), '(' + str(type(value).__name__) + ')')


def print_summary_table(summary, tool='Prowler', platform='AWS'):
    # Create a table with headers
    table = PrettyTable(['Service', 'Resources', 'Rules', 'Flagged Items', 'Unknown status', 'Checked Items', 'Severity'])

    # Add rows to the table
    for service, info in summary.items():
        if info['checked_items'] > 0:
            color = GREEN if info['flagged_items'] == 0 or info['max_level'] == 0 else YELLOW if info['max_level'] == 1 else ORANGE if info['max_level'] == 2 else RED
            severity = 'No issues' if color == GREEN else 'Low' if color == YELLOW else 'Medium' if color == ORANGE else 'High' if color == RED else 'Unknown'
            flagged_items = f"{color}{info['flagged_items']}{NC}"
            unknown_status = f"{ORANGE}{info['unknown_status']}{NC}" if info['unknown_status'] > 0 else info['unknown_status']
            service = f'{color}{service}{NC}'
            table.add_row([service, info['resources_count'], info['rules_count'], flagged_items, unknown_status, info['checked_items'], severity])

    print(f'\n\nSummary - Tool: {tool}, Platform: {platform}, Severity: {GREEN}No issues{NC} - {YELLOW}Low{NC} - {ORANGE}Medium{NC} - {RED}High{NC}')
    print(table)


def print_scoutsuite_table_old(summary):
    # Create a table with headers
    table = PrettyTable(['Service', 'Resources', 'Rules', 'Flagged Items', 'Checked Items'])

    # Add rows to the table
    for service, info in summary.items():
        if info['checked_items'] > 0:
            color = 'green' if info['max_level'] == 'info' or info['flagged_items'] == 0 else 'yellow' if info['max_level'] == 'warning' else 'red'
            flagged_items = colored(info['flagged_items'], color)
            service = colored(service, color)
            table.add_row([service, info['resources_count'], info['rules_count'], flagged_items, info['checked_items']])

    print(f'\n\nScoutSuite Summary, color legend: {GREEN}No issues{NC} - {YELLOW}Warning{NC} - {RED}Danger{NC}')
    print(table)


def load_csv_files_to_dataframe(directory):
    # Dictionary to hold dataframes
    dataframes = {}
    
    # Find all CSV files within the directory structure
    csv_files = glob.glob(f'{directory}/**/*.csv', recursive=True)
    
    for file_path in csv_files:
        # Extract a meaningful key from the file path (e.g., the file name without extension)
        key = os.path.splitext(os.path.basename(file_path))[0]
        
        # Load the CSV file into a DataFrame
        df = pd.read_csv(file_path)
        
        # Store the DataFrame in the dictionary
        dataframes[key] = df
    
    return dataframes


def print_summary_table(summary, tool='Prowler', platform='AWS'):
    # Create a table with headers
    table = PrettyTable(['Service', 'Resources', 'Rules', 'Flagged Items', 'Unknown status', 'Checked Items', 'Severity'])

    # Add rows to the table
    for service, info in summary.items():
        if info['checked_items'] > 0:
            color = GREEN if info['flagged_items'] == 0 or info['max_level'] == 0 else YELLOW if info['max_level'] == 1 else ORANGE if info['max_level'] == 2 else RED
            severity = 'No issues' if color == GREEN else 'Low' if color == YELLOW else 'Medium' if color == ORANGE else 'High' if color == RED else 'Unknown'
            flagged_items = f"{color}{info['flagged_items']}{NC}"
            unknown_status = f"{ORANGE}{info['unknown_status']}{NC}" if info['unknown_status'] > 0 else info['unknown_status']
            service = f"{color}{service}{NC}"
            table.add_row([service, info['resources_count'], info['rules_count'], flagged_items, unknown_status, info['checked_items'], severity])

    print(f'\n\nSummary - Tool: {tool}, Platform: {platform}, Severity: {GREEN}No issues{NC} - {YELLOW}Low{NC} - {ORANGE}Medium{NC} - {RED}High{NC}')
    print(table)


def print_dataframe_pretty(df, title, snip_limit=0, cloudfox_permissions=False):
    """
    Prints a pandas DataFrame in a pretty table format with optional row limiting.

    This function takes a DataFrame and a title to print the DataFrame in a formatted table. It limits the number of rows
    displayed based on the snip_limit parameter. For CloudFox permissions tables, it can display the full table or limit
    the rows to 25 based on the cloudfox_permissions flag.

    Parameters:
    - df (pandas.DataFrame): The DataFrame to print.
    - title (str): The title of the table to be printed.
    - snip_limit (int, optional): The maximum number of rows to display. Defaults to 0, which shows all rows.
    - cloudfox_permissions (bool, optional): If True and the table is a CloudFox permissions table, display all rows.
      Otherwise, limit to 25 rows. Defaults to False.

    Returns:
    - None
    """

    # Adjust snip_limit for CloudFox permissions tables if cloudfox_permissions is False
    if title == 'CloudFox - aws:permissions' and not cloudfox_permissions:
        snip_limit = 25 if (snip_limit == 0 or not snip_limit) else min(snip_limit, 25)

    # Check if snip_limit is set and greater than 0
    if snip_limit is not None and snip_limit > 0:
        num_entries = len(df)
        if num_entries > snip_limit:
            # Slice the DataFrame to the first snip_limit rows
            df = df.head(snip_limit)
            snipped = True
        else:
            snipped = False
    else:
        snipped = False
        num_entries = len(df)
    
    # Extract DataFrame columns and use them as table headers
    table = PrettyTable(df.columns.tolist())
    table.min_width = 15  # Set a minimum width for the table
    table.max_table_width = os.get_terminal_size().columns # Set the table width to the terminal width
    table.align = 'l'  # Align the text to the left
    
    # Add rows to the table
    for index, row in df.iterrows():
        table.add_row(row.tolist())
    
    # Print the table with a title
    print(f'\n\n{title}')
    print(table)
    
    # If snipping occurred, print a snip line
    if snipped:
        print(f'...and {num_entries - snip_limit} more entries')


# ###### Extract CloudSploit check details as severity is not exported in report
def extract_cloudsploit_aws_check_details():
    directory = 'tools/cloudsploit/plugins/aws/'
    check_details = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.js') and not file.endswith('.spec.js'):
                with open(os.path.join(root, file), 'r') as f:
                    content = f.read()
                    title = re.search(r"title:\s*'([^']+)',", content)
                    severity = re.search(r"severity:\s*'([^']+)',", content)
                    description = re.search(r"description:\s*'([^']+)',", content)
                    more_info = re.search(r"more_info:\s*'([^']+)',", content)
                    service = os.path.basename(root)
                    check_details.append({
                        'checkname': os.path.splitext(file)[0],
                        'title': title.group(1) if title else '',
                        'severity': severity.group(1) if severity else '',
                        'description': description.group(1) if description else '',
                        'more_info': more_info.group(1) if more_info else '',
                        'service': service
                    })
    check_details.sort(key=lambda x: (x['service'], x['checkname']))
    return check_details

# ###### Extract CloudSploit check details as severity is not exported in report
def extract_cloudsploit_azure_check_details():
    directory = 'tools/cloudsploit/plugins/azure/'
    check_details = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.js') and not file.endswith('.spec.js'):
                with open(os.path.join(root, file), 'r') as f:
                    content = f.read()
                    title = re.search(r"title:\s*'([^']+)',", content)
                    severity = re.search(r"severity:\s*'([^']+)',", content)
                    description = re.search(r"description:\s*'([^']+)',", content)
                    more_info = re.search(r"more_info:\s*'([^']+)',", content)
                    service = os.path.basename(root)
                    check_details.append({
                        'checkname': os.path.splitext(file)[0],
                        'title': title.group(1) if title else '',
                        'severity': severity.group(1) if severity else '',
                        'description': description.group(1) if description else '',
                        'more_info': more_info.group(1) if more_info else '',
                        'service': service
                    })
    check_details.sort(key=lambda x: (x['service'], x['checkname']))
    return check_details


def combine_and_save_csv_files(csv_files, combined_dir, delimiter):
    """
    Combines CSV files listed in the csv_files dictionary into single files in the combined_dir directory.
    csv_files: Dictionary with relative path as keys and list of file paths to combine as values.
    combined_dir: Directory where combined CSV files will be saved.
    delimiter: Delimiter used for reading and writing CSV files.
    """
    for csv_rel_path, file_paths in csv_files.items():
        # print(f'Combining {csv_rel_path} with filepaths {file_paths}...')
        combined_file_path = os.path.join(combined_dir, csv_rel_path)
        combined_file_dir = os.path.dirname(combined_file_path)
        if not os.path.exists(combined_file_dir):
            os.makedirs(combined_file_dir)
        
        combined_df = pd.concat([pd.read_csv(f, delimiter=delimiter) for f in file_paths]).drop_duplicates()
        combined_df.to_csv(combined_file_path, sep=delimiter, index=False)


def combine_and_save_json_files(json_files, combined_dir):
    combined_data = []
    for json_file in json_files:
        with open(json_file, 'r') as f:
            data = json.load(f)
            combined_data.extend(data)
    
    combined_file_path = os.path.join(combined_dir, 'combined_data.ocsf.json')
    with open(combined_file_path, 'w') as f:
        json.dump(combined_data, f, indent=4)


# Function that combines the findings from multiple ScoutSuite JSON files. Not used anymore, as combining profiles is done in a different way.
def debug_combine_scoutsuite_findings(output_path='output', provider='aws', profile='default'):
    combined_summary = {}
    severity_mapping = {'unknown': 0, 'info': 1, 'warning': 2, 'danger': 3}

    # Find all .js files in the output_path directory
    js_files = glob.glob(f'{output_path}/{profile}/scoutsuite/scoutsuite-results/scoutsuite_results_*.js')
    if not js_files:
        print("No JS files found in the output directory.")
        return combined_summary

    for js_file in js_files:
        with open(js_file, 'r') as f:
            data = f.read()
        # Remove the assignment part ('scoutsuite_results =') from the data
        json_data = data.replace('scoutsuite_results =', '').strip()
        # Parse the JSON data
        parsed_data = json.loads(json_data)

        for service, info in parsed_data['last_run']['summary'].items():
            if service in combined_summary:
                combined_summary[service]['checked_items'] += info.get('checked_items', 0)
                combined_summary[service]['flagged_items'] += info.get('flagged_items', 0)
                combined_summary[service]['max_level'] = max(combined_summary[service]['max_level'], severity_mapping.get(info.get('max_level', 'unknown'), 0))
                combined_summary[service]['unknown_status'] += info.get('unknown_status', 0)
                combined_summary[service]['resources_count'] += info.get('resources_count', 0)
                combined_summary[service]['rules_count'] += info.get('rules_count', 0)
            else:
                combined_summary[service] = {
                    'checked_items': info.get('checked_items', 0),
                    'flagged_items': info.get('flagged_items', 0),
                    'max_level': severity_mapping.get(info.get('max_level', 'unknown'), 0),
                    'unknown_status': info.get('unknown_status', 0),
                    'resources_count': info.get('resources_count', 0),
                    'rules_count': info.get('rules_count', 0),
                }

    return combined_summary

def combine_profiles(output_path='output', provider='aws'):
    combined_dir = f'{output_path}/combined_profiles/'
    if not os.path.exists(combined_dir):
        os.makedirs(combined_dir)
    profiles = [f.name for f in os.scandir(output_path) if f.is_dir()]
    combined__category_dfs = {}
    for profile in profiles:
        if profile == 'combined_profiles':
            continue
        mapped_checks = categorize_all_tools_issues(os.path.join(output_path, profile), provider, print_categories=False)
        for category, df in mapped_checks.items():
            if category not in combined__category_dfs:
                combined__category_dfs[category] = df
            else:
                combined__category_dfs[category] = pd.concat([combined__category_dfs[category], df], ignore_index=True).drop_duplicates()


    # Define severity order for sorting
    severity_order = {'Low': 1, 'Warning': 2, 'Medium': 3, 'Danger': 4, 'High': 5, 'Critical': 6}

    for name, df in combined__category_dfs.items():
        # Rank severity and sort dataframes based on severity
        df['severity_rank'] = df['severity'].map(severity_order).fillna(0)
        df.sort_values('severity_rank', inplace=True, ascending=False)
        df.drop('severity_rank', axis=1, inplace=True)
        
        # Print dataframe in a pretty format
        print_dataframe_pretty(df, name)
        

    big_df = pd.DataFrame()
    for name, df in combined__category_dfs.items():
        # Add 'category' column with the name of the category
        df['category'] = name
        # Append the modified DataFrame to the big DataFrame
        big_df = pd.concat([big_df, df], ignore_index=True)

    # Sort the big DataFrame if needed, first by category and then by severity
    big_df.sort_values(by=['category', 'severity'], inplace=True)

    # Define the base name for output files
    output_base = f'{combined_dir}/{provider}_categorized_issues'

    # Export the big DataFrame to .xlsx, .csv, and .txt formats
    big_df.to_excel(f'{output_base}.xlsx', index=False)
    big_df.to_csv(f'{output_base}.csv', index=False)

    # For .txt output, simulate the pretty print format
    with open(f'{output_base}.txt', 'w') as txt_file:
        txt_file.write(big_df.to_string(index=False))  # Simplified version of pretty print

        

def summarize_prowler(output_path='output', provider='aws', print_summary=True):
    '''
    Analyzes the Prowler output files and prints a summary table.

    Args:
        output_path (str, optional): The path to the directory containing the Prowler output files. Defaults to 'output'.
        provider (str, optional): The cloud provider name. Defaults to 'aws'.
        print_summary (bool, optional): Whether to print the summary table. Defaults to True.

    Returns:
        summary (dict): A dictionary containing the summary information.
    '''
    # Find the .csv file in the output_path directory
    csv_files = glob.glob(f'{output_path}/prowler/prowler-output-*.csv')

    if not csv_files:
        print(f'{RED}{BOLD}No CSV file found in the output directory, skipping summary for Prowler!!{NC}')
        return

    # Read the first .csv file found
    df = pd.read_csv(csv_files[0], sep=';')

    # Create a summary object
    severity_mapping = {'low': 1, 'medium': 2, 'high': 3}
    summary = {}
    services = df['SERVICE_NAME'].unique()
    for service in services:
        service_df = df[df['SERVICE_NAME'] == service]
        failed_items_df = service_df[service_df['STATUS'] == 'FAIL']
        max_severity = failed_items_df['SEVERITY'].map(severity_mapping).max() if not failed_items_df.empty else 0
        summary[service] = {
            'checked_items': len(service_df),
            'flagged_items': len(failed_items_df),
            'max_level': max_severity,
            'unknown_status': len(service_df[service_df['STATUS'] == 'MANUAL']),
            'resources_count': service_df['RESOURCE_UID'].nunique(),
            'rules_count': service_df['CHECK_ID'].nunique(),
        }
    # Print the summary as a table
    if print_summary:
        print_summary_table(summary, 'Prowler', provider)
    return summary




def summarize_scoutsuite(output_path='output', provider='aws', print_summary=True):
    '''
    Analyzes the ScoutSuite results and prints a summary table.

    Args:
        output_path (str): The path to the output directory where ScoutSuite results are stored.
        provider (str): The cloud provider for which the analysis is performed.
        print_summary (bool, optional): Whether to print the summary table. Defaults to True.

    Returns:
        summary (dict): A dictionary containing the summary information.
    '''
    # Find the .js file in the output_path directory
    js_files = glob.glob(f'{output_path}/scoutsuite/scoutsuite-results/scoutsuite_results_*.js')

    if not js_files:
        print(f'{RED}{BOLD}No JS file found in the output directory, skipping summary for ScoutSuite!!{NC}')
        return

    # Read the first .js file found
    with open(js_files[0], 'r') as f:
        data = f.read()

    # Remove the assignment part ('scoutsuite_results =') from the data
    json_data = data.replace('scoutsuite_results =', '').strip()

    # Parse the JSON data
    parsed_data = json.loads(json_data)

    # Create a summary object
    severity_mapping = {'unknown': 0, 'info': 1, 'warning': 2, 'danger': 3}
    summary = {}
    for service, info in parsed_data['last_run']['summary'].items():
        summary[service] = {
            'checked_items': info.get('checked_items', 0),
            'flagged_items': info.get('flagged_items', 0),
            'max_level': severity_mapping.get(info.get('max_level', 'unknown'), 0),
            'unknown_status': 0, # TODO: check if scoutsuite indeed doesn't report failed checks
            'resources_count': info.get('resources_count', 0),
            'rules_count': info.get('rules_count', 0),
        }
    # Print the summary as a table
    if print_summary:
        print_summary_table(summary, 'ScoutSuite', provider)
    return summary


def summarize_cloudsploit(output_path='output', provider='aws', print_summary=True):
    '''
    Analyzes the CloudSploit output file and prints a summary table.

    Args:
        output_path (str, optional): The path to the output directory. Defaults to 'output'.
        provider (str, optional): The cloud provider. Defaults to 'aws'.
        print_summary (bool, optional): Whether to print the summary table. Defaults to True.

    Returns:
        summary (dict): A dictionary containing the summary information.
    '''
    # Find the .csv file in the output_path directory
    csv_files = glob.glob(f'{output_path}/cloudsploit/cloudsploit-output.csv')

    if not csv_files:
        print(f'{RED}{BOLD}No CSV file found in the output directory, skipping summary for CloudSploit!!{NC}')
        return
    
    # Read the first .csv file found
    df = pd.read_csv(csv_files[0], sep=',')

    # Create a summary object
    summary = {}
    services = df['category'].unique()  
    for service in services:
        service_df = df[df['category'] == service]
        # service_df = service_df[service_df['statusWord'].isin(['FAIL', 'UNKNOWN', 'OK'])]
        summary[service] = {
            'checked_items': len(service_df),
            'flagged_items': len(service_df[service_df['statusWord'] == 'FAIL']),
            # TODO: implement max_level based on extract_cloudsploit_check_details()
            'max_level': 3 if len(service_df[service_df['statusWord'] == 'FAIL']) > 0 else 0,
            'unknown_status': len(service_df[service_df['statusWord'] == 'UNKNOWN']),
            'resources_count': service_df['resource'].nunique(),
            'rules_count': service_df['title'].nunique(),
        }  
    # Print the summary as a table
    if print_summary:
        print_summary_table(summary, 'CloudSploit', provider)
    return summary
        

def summarize_cloudfox(output_path='output', provider='aws', print_summary=True):
    '''
    Summarizes CloudFox output by loading its output CSV files and printing the results in a pretty table format.

    Parameters:
    - output_path (str, optional): The base directory where CloudFox output is stored. Defaults to 'output'.
    - provider (str, optional): The cloud provider for which the analysis was performed. Defaults to 'aws'.
    - print_summary (bool, optional): If True, prints the summary tables to the console. Defaults to True.

    Returns:
    - dict: A dictionary of pandas DataFrames keyed by the CSV file names, representing the analyzed CloudFox output.
    '''
    dataframes = load_csv_files_to_dataframe(f'{output_path}/cloudfox/cloudfox-output')
    if not dataframes:
        print(f'{RED}{BOLD}No CSV files found in the output directory, skipping summary for CloudFox!!{NC}')
        return
    # Print all the dataframes using the new pretty print function
    if print_summary:
        for key, df in dataframes.items():
            print_dataframe_pretty(df, f'CloudFox - {provider}:' + key)
    return dataframes


def summarize_monkey365(output_path='monkey-reports', provider='azure', print_summary=True):
    '''
    Analyze Monkey365 output and print the results in a pretty table format.
    '''
    dataframes = load_csv_files_to_dataframe(f'{output_path}/monkey365/')
    if not dataframes:
        print(f'{RED}{BOLD}No CSV files found in the output directory, skipping summary for Monkey365!!{NC}')
        return
    # Print all the dataframes using the new pretty print function
    if print_summary:
        for key, df in dataframes.items():
            print_dataframe_pretty(df, f'Monkey365 - {provider}:' + key)
    return dataframes


def parse_checks():
    """
    Parses the checks_mappings.txt, prowler_all_aws_checks.txt, scoutsuite_all_aws_checks.txt,
    and cloudsploit_all_aws_checks.txt files to create a mapping of categories to checks and
    checks to categories.

    Returns:
        A tuple containing two dictionaries:
        - categories_to_checks: A dictionary mapping categories to a list of checks.
        - checks_to_categories: A dictionary mapping checks to their corresponding category.
    """
    categories_to_checks = {}
    checks_to_categories = {}
    current_category = None

    categories_to_checks['Uncategorized issues'] = []
    with open('checks_mappings.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith('### '):
                current_category = line[4:]
                categories_to_checks[current_category] = []
            elif line.startswith('- ') and current_category:
                check = line[2:]
                categories_to_checks[current_category].append(check)
                checks_to_categories[check] = current_category

    with open('prowler_all_aws_checks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            if line not in checks_to_categories:
                categories_to_checks['Uncategorized issues'].append(line)
                checks_to_categories[line] = 'Uncategorized issues'

    with open('scoutsuite_all_aws_checks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            if line not in checks_to_categories:
                categories_to_checks['Uncategorized issues'].append(line)
                checks_to_categories[line] = 'Uncategorized issues'

    with open('cloudsploit_all_aws_checks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            if line not in checks_to_categories:
                categories_to_checks['Uncategorized issues'].append(line)
                checks_to_categories[line] = 'Uncategorized issues'

    return categories_to_checks, checks_to_categories


def analyze_prowler(output_path, provider, checks_to_categories, category_dfs={}):
    """
    Analyzes the Prowler output from the specified output path and categorizes the failed checks.

    Args:
        output_path (str): The path to the directory containing the Prowler output files.
        provider (str): The cloud provider name.
        checks_to_categories (dict): A dictionary mapping Prowler check IDs to categories.
        category_dfs (dict, optional): A dictionary of existing category DataFrames. Defaults to an empty dictionary.

    Returns:
        dict: A dictionary containing the categorized failed checks.

    """
    # Find the .csv file in the output_path directory
    csv_files = glob.glob(f'{output_path}/prowler/prowler-output-*.csv')
    if not csv_files:
        print(f'{YELLOW}{BOLD}No CSV file found in the output directory, skipping analysis for Prowler!!{NC}')
        return category_dfs

    # Read the first .csv file found
    df = pd.read_csv(csv_files[0], sep=';')
    print(f'{GREEN}Analyzing Prowler output...{NC}')
    print(f'{GREEN}Total checks: {len(df)}{NC}')
    print(f'{GREEN}Total categories: {len(df["SERVICE_NAME"].unique())}{NC}')
    print(f'{GREEN}Total resources: {df["RESOURCE_UID"].nunique()}{NC}')
    print(f'{GREEN}Total rules: {df["CHECK_ID"].nunique()}{NC}')
    print(f'{GREEN}Total flagged items: {len(df[df["STATUS"] == "FAIL"])}{NC}')
    print(f'{GREEN}Total unknown status: {len(df[df["STATUS"] == "MANUAL"])}{NC}')
    print(f'{GREEN}Total passed checks: {len(df[df["STATUS"] == "PASS"])}{NC}')
    print(f'{GREEN}Total ignored checks: {len(df[df["STATUS"] == "IGNORED"])}{NC}')

    category_data = {}
    # for all failed checks, create a df for each category with the check_id, resource_uid, severity, and tool (=Prowler)
    failed_checks = df[df["STATUS"] == "FAIL"]
    for index, row in failed_checks.iterrows():
        check_id = row["CHECK_ID"]
        category = checks_to_categories.get(check_id, 'Uncategorized issues')
        category_data.setdefault(category, [])
        category_data[category].append({
            'check_id': check_id,
            'resource_uid': row["RESOURCE_UID"],
            'severity': row["SEVERITY"],
            'tool': 'Prowler'
        })

    # Create new category DataFrames
    new_category_dfs = {category: pd.DataFrame(data) for category, data in category_data.items()}

    # Remove duplicates from each category DataFrame and change severity to title case
    for category, df in new_category_dfs.items():
        df.drop_duplicates(inplace=True)
        df['severity'] = df['severity'].str.capitalize()

    # Concatenate with existing category DataFrames
    if category_dfs is not None:
        for category, df in new_category_dfs.items():
            if category in category_dfs:
                category_dfs[category] = pd.concat([category_dfs[category], df]).drop_duplicates()
            else:
                category_dfs[category] = df

    return category_dfs


def analyze_scoutsuite(output_path, provider, checks_to_categories, category_dfs={}):
    """
    Analyzes the ScoutSuite output from the specified output path and categorizes the failed checks.

    Args:
        output_path (str): The path to the directory containing the ScoutSuite output files.
        provider (str): The cloud provider name.
        checks_to_categories (dict): A dictionary mapping ScoutSuite check IDs to categories.
        category_dfs (dict, optional): A dictionary of existing category DataFrames. Defaults to an empty dictionary.

    Returns:
        dict: A dictionary containing the categorized failed checks.

    """
    # Find the .js file in the output_path directory
    js_files = glob.glob(f'{output_path}/scoutsuite/scoutsuite-results/scoutsuite_results_*.js')
    if not js_files:
        print(f'{YELLOW}{BOLD}No JS file found in the output directory, skipping analysis for ScoutSuite!!{NC}')
        return category_dfs

    # Read the first .js file found
    with open(js_files[0], 'r') as f:
        data = f.read()

    # Remove the assignment part ('scoutsuite_results =') from the data
    json_data = data.replace('scoutsuite_results =', '').strip()

    # Parse the JSON data
    parsed_data = json.loads(json_data)

    print(f'{GREEN}Analyzing ScoutSuite output...{NC}')
    print(f'{GREEN}Total categories: {len(parsed_data["last_run"]["summary"])}{NC}')
    print(f'{GREEN}Total resources: {sum([info.get("resources_count", 0) for info in parsed_data["last_run"]["summary"].values()])}{NC}')
    print(f'{GREEN}Total rules: {sum([info.get("rules_count", 0) for info in parsed_data["last_run"]["summary"].values()])}{NC}')
    print(f'{GREEN}Total flagged items: {sum([info.get("flagged_items", 0) for info in parsed_data["last_run"]["summary"].values()])}{NC}')
    print(f'{GREEN}Total unknown status: {sum([info.get("unknown_status", 0) for info in parsed_data["last_run"]["summary"].values()])}{NC}')
    print(f'{GREEN}Total checked items: {sum([info.get("checked_items", 0) for info in parsed_data["last_run"]["summary"].values()])}{NC}')

    category_data = {}

    # for all failed checks, create a df for each category with the check_id, resource_uid, severity, and tool (=ScoutSuite)
    for service, info in parsed_data['services'].items():
        for finding, finding_info in info['findings'].items():
            if 'flagged_items' in finding_info and finding_info['flagged_items'] > 0:
                category = checks_to_categories.get(finding, 'Uncategorized issues')
                category_data.setdefault(category, [])
                for item in finding_info.get('items', []):
                    category_data[category].append({
                        'check_id': finding,
                        'resource_uid': item,
                        'severity': finding_info.get('level', ''),
                        'tool': 'ScoutSuite'
                    })

    # Create new category DataFrames
    new_category_dfs = {category: pd.DataFrame(data) for category, data in category_data.items()}

    # Remove duplicates from each category DataFrame and change severity to title case
    for category, df in new_category_dfs.items():
        df.drop_duplicates(inplace=True)
        df['severity'] = df['severity'].str.capitalize()
        # print_dataframe_pretty(df, f'ScoutSuite - {provider} - {category}')

    # Concatenate with existing category DataFrames
    if category_dfs is not None:
        for category, df in new_category_dfs.items():
            if category in category_dfs:
                category_dfs[category] = pd.concat([category_dfs[category], df]).drop_duplicates()
            else:
                category_dfs[category] = df

    return category_dfs


def analyze_cloudsploit(output_path, provider, checks_to_categories, category_dfs={}):
    """
    Analyzes the CloudSploit output from the specified output path and categorizes the failed checks.

    Args:
        output_path (str): The path to the directory containing the CloudSploit output files.
        provider (str): The cloud provider name.
        checks_to_categories (dict): A dictionary mapping CloudSploit check IDs to categories.
        category_dfs (dict, optional): A dictionary of existing category DataFrames. Defaults to an empty dictionary.

    Returns:
        dict: A dictionary containing the categorized failed checks.

    """
    # Find the .csv file in the output_path directory
    csv_files = glob.glob(f'{output_path}/cloudsploit/cloudsploit-output.csv')
    if not csv_files:
        print(f'{YELLOW}{BOLD}No CSV file found in the output directory, skipping analysis for CloudSploit!!{NC}')
        return category_dfs

    # Read the first .csv file found
    df = pd.read_csv(csv_files[0], sep=',')

    print(f'{GREEN}Analyzing CloudSploit output...{NC}')
    print(f'{GREEN}Total categories: {len(df["category"].unique())}{NC}')
    print(f'{GREEN}Total resources: {df["resource"].nunique()}{NC}')
    print(f'{GREEN}Total rules: {df["title"].nunique()}{NC}')
    print(f'{GREEN}Total flagged items: {len(df[df["statusWord"] == "FAIL"])}{NC}')
    print(f'{GREEN}Total unknown status: {len(df[df["statusWord"] == "UNKNOWN"])}{NC}')
    print(f'{GREEN}Total checked items: {len(df)}{NC}')

    check_details = extract_cloudsploit_aws_check_details()
    category_data = {}

    # for all failed checks, create a df for each category with the check_id, resource_uid, severity, and tool (=CloudSploit)
    failed_checks = df[df["statusWord"] == "FAIL"]
    for index, row in failed_checks.iterrows():
        check_id = row["title"]
        category = checks_to_categories.get(check_id, 'Uncategorized issues')
        category_data.setdefault(category, [])
        category_data[category].append({
            'check_id': check_id,
            'resource_uid': str(row["resource"]) + ' (' + row["region"] + ')',
            'severity': next((check['severity'] for check in check_details if check['title'] == check_id), ''),
            'tool': 'CloudSploit'
        })

    # Create new category DataFrames
    new_category_dfs = {category: pd.DataFrame(data) for category, data in category_data.items()}

    # Remove duplicates from each category DataFrame and change severity to title case
    for category, df in new_category_dfs.items():
        df.drop_duplicates(inplace=True)
        df['severity'] = df['severity'].str.capitalize()

    # Concatenate with existing category DataFrames
    if category_dfs is not None:
        for category, df in new_category_dfs.items():
            if category in category_dfs:
                category_dfs[category] = pd.concat([category_dfs[category], df]).drop_duplicates()
            else:
                category_dfs[category] = df

    return category_dfs



def categorize_all_tools_issues(output_path, provider, print_categories=True):
    """
    Categorizes issues from different tools and exports the categorized data to various formats.

    Args:
        output_path (str): The path where the output files will be saved.
        provider (str): The name of the cloud provider.
        print_categories (bool, optional): Whether to print the categorized dataframes. Defaults to True.

    Returns:
        dict: A dictionary containing the categorized issues.
    """
    # Parse checks and map them to categories
    checks_dict, checks_to_categories = parse_checks()
    mapped_checks = {}
    
    # Analyze output from different tools and categorize issues
    mapped_checks = analyze_prowler(output_path, provider, checks_to_categories, mapped_checks)
    mapped_checks = analyze_scoutsuite(output_path, provider, checks_to_categories, mapped_checks)
    mapped_checks = analyze_cloudsploit(output_path, provider, checks_to_categories, mapped_checks)
    
    # Define severity order for sorting
    severity_order = {'Low': 1, 'Warning': 2, 'Medium': 3, 'Danger': 4, 'High': 5, 'Critical': 6}

    for name, df in mapped_checks.items():
        # Rank severity and sort dataframes based on severity
        df['severity_rank'] = df['severity'].map(severity_order).fillna(0)
        df.sort_values('severity_rank', inplace=True, ascending=False)
        df.drop('severity_rank', axis=1, inplace=True)
        
        # Print dataframe in a pretty format
        if print_categories:
            print_dataframe_pretty(df, name)
        
    # Initialize an empty DataFrame to hold all categories
    big_df = pd.DataFrame()

    for name, df in mapped_checks.items():
        # Add 'category' column with the name of the category
        df['category'] = name
        # Append the modified DataFrame to the big DataFrame
        big_df = pd.concat([big_df, df], ignore_index=True)

    # Sort the big DataFrame if needed, first by category and then by severity
    big_df.sort_values(by=['category', 'severity'], inplace=True)

    # Define the base name for output files
    output_base = f'{output_path}/{provider}_categorized_issues'

    # Export the big DataFrame to .xlsx, .csv, and .txt formats
    big_df.to_excel(f'{output_base}.xlsx', index=False)
    big_df.to_csv(f'{output_base}.csv', index=False)

    # For .txt output, simulate the pretty print format
    with open(f'{output_base}.txt', 'w') as txt_file:
        txt_file.write(big_df.to_string(index=False))  # Simplified version of pretty print

    return mapped_checks


def main():
    """
    Analyzes the output folders for different cloud providers.

    This function retrieves the list of output folders, sorts them by last modified time,
    and prompts the user to select the output folder(s) to analyze. It then extracts the
    provider from the folder name, and runs various summarization and categorization functions
    on the selected folder.
    
    Returns:
        None
    """
    try:
        output_base_path = 'output/'
        # Get folders and sort them by last modified time
        output_folders = sorted(
            [f.name for f in os.scandir(output_base_path) if f.is_dir()],
            key=lambda x: os.path.getmtime(os.path.join(output_base_path, x)),
            reverse=True  # Newest first
        )

        selected_folders = selectionmenu.make_menu_selection(output_folders, menu_text='Select the output folder(s) to analyze:', print_results=False, bool_input=True, return_as_str=True)
        if not selected_folders:
            print("No folder selected. Exiting.")
            return

        for selected_folder in selected_folders:
            print(f'{GREEN}Selected folder: {selected_folder}{NC}')

            selected_folder_path = os.path.join(output_base_path, selected_folder)
            
            # Extract the provider from the folder name
            provider = selected_folder.split('-')[0]  # Splits the folder name and takes the first part as the provider

            if provider not in ['azure', 'aws']:
                print(f"Unknown provider '{provider}'. Exiting.")
                continue

            # Run summarization and categorization functions on the selected folder
            summarize_prowler(selected_folder_path, provider)
            summarize_scoutsuite(selected_folder_path, provider)
            summarize_cloudsploit(selected_folder_path, provider)
            summarize_cloudfox(selected_folder_path, provider)
            summarize_monkey365(selected_folder_path, provider)
            categorize_all_tools_issues(selected_folder_path, provider)

    except FileNotFoundError:
        print("The specified folder does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

 
