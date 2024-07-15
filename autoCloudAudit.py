# Copyright (c) 2024 Guido Borst
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import authenticate, selectionmenu, analyze

import signal
import subprocess
import os
import json
import datetime
import time

# Colors for the terminal
GREEN = '\033[92m'
YELLOW = '\033[93m'
ORANGE = '\033[38;5;208m'
RED = '\033[91m'
BOLD = '\033[1m'
NC = '\033[0m'


def signal_handler(sig, frame):
    '''Signal handler function for handling SIGINT signals.'''
    print('Forwarding SIGINT to subprocess')
    global received_sigint, sigint_count
    sigint_count += 1
    received_sigint = True
    if sub_process:
        if sigint_count >= 3:
            print('Killing subprocess after 3 SIGINT signals')
            sub_process.kill()
        else:
            sub_process.send_signal(signal.SIGINT)

 
# Run a list of shell-commands in a directory
def run_commands_orig(commands, directory, print_output=True):
    '''Run a list of shell-commands in a directory and optionally print the output to the console.'''
    global sub_process, received_sigint, sigint_count
    received_sigint = False
    sigint_count = 0
    original_sigint_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)  # Register signal handler

    # Execute the command in the directory and wait for it to finish
    # Concatenate all commands into a single string, so that they can be executed in a single shell
    command_str = '; '.join(commands)

    # Execute the command in the directory and wait for it to finish
    sub_process = subprocess.Popen(command_str, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, cwd=directory, executable='/bin/bash')
    # Read the output line by line and print it to the console in real-time
    while True:
        output = sub_process.stdout.readline()
        if output == b'' and sub_process.poll() is not None:
            break
        if output and print_output:
            print(output.decode('utf-8').rstrip())

    # Print the error to the console
    error = sub_process.stderr.read()
    print(error.decode('utf-8'))

    signal.signal(signal.SIGINT, original_sigint_handler)  # Restore original signal handler
    return


def run_commands(commands, directory, print_output=True):
    '''
    Run a list of shell-commands in a directory and print the output to the console.

    Returns:
        bool: True if the command was interrupted by the user, False otherwise.
    '''
    command_str = '; '.join(commands)
    interrupted = False
    try:
        subprocess.run(command_str, shell=True, check=True, cwd=directory, executable='/bin/bash')
    except subprocess.CalledProcessError as e:
        print(f"Command '{e.cmd}' returned non-zero exit status {e.returncode}.")
    except KeyboardInterrupt:
        print('Command interrupted by user.')
        interrupted = True
    return interrupted



def create_temp_azure_app(subscription_id):
    '''
    Creates a temporary Azure app registration and saves the IDs to variables.

    Returns:
        dict: A dictionary containing clientid, clientsecret, spid, and clientsecretname.
    '''
    appregname = 'AutoCloudAudit_temp_App'
    clientsecretname = 'AutoCloudAudit_ScriptGenerated'
    enddate = subprocess.check_output(['date', '-d', '+1 month', '+%Y-%m-%d']).decode().strip()

    # Create app registration
    clientid = subprocess.check_output(['az', 'ad', 'app', 'create', '--display-name', appregname, '--query', 'appId', '--output', 'tsv']).decode().strip()
    clientsecret = subprocess.check_output(['az', 'ad', 'app', 'credential', 'reset', '--id', clientid, '--append', '--display-name', clientsecretname, '--end-date', enddate, '--query', 'password', '--output', 'tsv']).decode().strip()

    # Check if SPID already exists (if the app registration was created before but not cleaned up)
    sp_list_output = subprocess.check_output(['az', 'ad', 'sp', 'list', '--filter', f"appId eq '{clientid}'", '--query', '[].servicePrincipalNames', '--output', 'json']).decode().strip()
    print(sp_list_output)
    sp_list = json.loads(sp_list_output)
    print(sp_list)

    if sp_list:
        # SPID exists, use the existing SPID
        spid = sp_list[0][0]
        print(f'Service Principal already exists with ID: {spid}. Skipping creation.')
    else:
        # If SPID does not exist, create a new service principal
        spid = subprocess.check_output(['az', 'ad', 'sp', 'create', '--id', clientid, '--query', 'id', '--output', 'tsv']).decode().strip()
        # Wait for 10 seconds to allow the service principal to be created
        time.sleep(10)

    # Check if roles are already assigned
    roles_output = subprocess.check_output(['az', 'role', 'assignment', 'list', '--assignee', spid, '--query', '[].roleDefinitionName', '--output', 'json']).decode().strip()
    roles = json.loads(roles_output)
    required_roles = ['Security Reader', 'Log Analytics Reader']
    for role in required_roles:
        if role not in roles:
            # Assign role if not already assigned
            subprocess.run(['az', 'role', 'assignment', 'create', '--role', role, '--assignee', spid, '--scope', f'/subscriptions/{subscription_id}'])
        else:
            print(f"Role '{role}' is already assigned to SPID: {spid}. Skipping role assignment.")

    # Function continues...
    # Wait for 5 seconds after adding roles
    time.sleep(5)

    azure_app_credentials = {
        'clientid': clientid,
        'clientsecret': clientsecret,
        'spid': spid,
        'clientsecretname': clientsecretname
    }
    print(azure_app_credentials)
    return azure_app_credentials


def cleanup_temp_azure_app(clientid):
    '''
    Deletes a temporary Azure app registration and removes its role assignments.

    Args:
        clientid (str): The client ID of the app to delete.
    '''
    # Convert the client ID to the service principal ID
    spid = subprocess.check_output(['az', 'ad', 'sp', 'list', '--filter', f"appId eq '{clientid}'", '--query', '[].id', '--output', 'tsv']).decode().strip()

    # List role assignments for the service principal
    role_assignments = json.loads(subprocess.check_output(['az', 'role', 'assignment', 'list', '--assignee', spid, '--output', 'json']).decode().strip())

    # Remove role assignments
    for assignment in role_assignments:
        subprocess.run(['az', 'role', 'assignment', 'delete', '--ids', assignment['id']])

    # Delete the app registration
    subprocess.run(['az', 'ad', 'app', 'delete', '--id', clientid])


def run_prowler(provider='aws', authmethod='cli', profile='default', output_dir='output'):
    '''
    Run Prowler audit tool for cloud providers.

    Args:
        provider (str, optional): The cloud provider to run Prowler on. Defaults to 'aws'.
        authmethod (str, optional): The authentication method to use. Defaults to 'cli'.
        profile (str, optional): The AWS profile/Azure subscription to use for authentication and auditing. Defaults to 'default'.

    Returns:
        None
    '''
    prowler_dir = os.path.abspath(os.path.join(os.getcwd(), 'tools', 'prowler'))
    if not authenticate.check_logged_in_cli(provider):
        print(f'Not logged into {provider}')
        return

    if provider == 'aws':
        if authmethod == 'cli':
            cmd = f'prowler aws -p {profile} -o {output_dir}/{profile}/prowler'
        else:
            cmd = f'prowler aws -o {output_dir}/{profile}/prowler'

    elif provider == 'azure':
        if authmethod == 'cli':
            cmd = f'prowler azure --az-cli-auth -o {output_dir}/{profile}/prowler'
        else:
            cmd = f'prowler azure -o {output_dir}/{profile}/prowler'

    print(f'Running Prowler with command: "{cmd}"')
    interrupted = run_commands(['source venv_prowler/bin/activate', cmd, f'ln -s {output_dir}/{profile}/prowler/ {output_dir}/{profile}/prowler/output', 'deactivate', f"echo '{GREEN}{BOLD}Prowler run completed!{NC}'"], prowler_dir, print_output=True)
    return interrupted


def run_scoutsuite(provider='aws', authmethod='cli', profile='default', output_dir='output'):
    '''
    Run ScoutSuite audit tool for cloud providers.

    Args:
        provider (str, optional): The cloud provider to run ScoutSuite on. Defaults to 'aws'.
        authmethod (str, optional): The authentication method to use. Defaults to 'cli'.
        profile (str, optional): The AWS profile/Azure subscription to use for authentication and auditing. Defaults to 'default'.

    Returns:
        None
    '''
    scoutsuite_dir = os.path.abspath(os.path.join(os.getcwd(), 'tools', 'scoutsuite'))
    if not authenticate.check_logged_in_cli(provider):
        print(f'Not logged into {provider}')
        return

    if provider == 'aws':
        if authmethod == 'cli':
            cmd = f"scout aws -p {profile} --report-dir {output_dir}/{profile}/scoutsuite"
        else:
            cmd = f"scout aws --report-dir {output_dir}/{profile}/scoutsuite"

    elif provider == "azure":
        if authmethod == "cli":
            cmd = f"scout azure --cli --report-dir {output_dir}/{profile}/scoutsuite"
        else:
            cmd = f"scout azure --report-dir {output_dir}/{profile}/scoutsuite"

    print(f'Running ScoutSuite with command: "{cmd}"')
    interrupted = run_commands(['source venv_scoutsuite/bin/activate', cmd, 'deactivate', f"echo '{GREEN}{BOLD}ScoutSuite run completed!{NC}'"], scoutsuite_dir, print_output=True)
    return interrupted


def run_cloudfox(provider="aws", authmethod="cli", profile='default', output_dir='output'):
    """
    Run CloudFox audit tool for cloud providers.

    Args:
        provider (str, optional): The cloud provider to run CloudFox on. Defaults to "aws".
        authmethod (str, optional): The authentication method to use. Defaults to "cli".
        profile (str, optional): The AWS profile/Azure subscription to use for authentication and auditing. Defaults to "default".

    Returns:
        None
    """
    cloudfox_dir = os.path.abspath(os.path.join(os.getcwd(), "tools", "cloudfox"))    
    if not authenticate.check_logged_in_cli(provider):
        print(f"Not logged into {provider}-CLI")
        return

    if provider == "aws":
        if authmethod == "cli":
            cmd = f"./cloudfox aws -p {profile} --outdir {output_dir}/{profile}/cloudfox all-checks"
        else:
            cmd = f"./cloudfox aws --outdir {output_dir}/{profile}/cloudfox all-checks"

    elif provider == "azure":
        if authmethod == "cli":
            tenant_id = authenticate.get_azure_credentials(profile).get('directory_id')
            cmds = [
                f"./cloudfox azure --outdir {output_dir}/{profile}/cloudfox inventory -t {tenant_id}",
                f"./cloudfox azure --outdir {output_dir}/{profile}/cloudfox rbac -t {tenant_id}",
                f"./cloudfox azure --outdir {output_dir}/{profile}/cloudfox storage -t {tenant_id}",
                f"./cloudfox azure --outdir {output_dir}/{profile}/cloudfox vms -t {tenant_id}",
                f"./cloudfox azure --outdir {output_dir}/{profile}/cloudfox whoami -t {tenant_id}"
            ]
        else:
            cmds = [f"./cloudfox azure --outdir {output_dir}/{profile}/cloudfox inventory rbac storage vms whoami"]
        cmd = '; '.join(cmds)


    print(f'Running CloudFox with command: "{cmd}"')
    interrupted = run_commands([cmd, f'echo "{GREEN}{BOLD}CloudFox run completed!"{NC}'], cloudfox_dir, print_output=True)
    return interrupted
        

def run_cloudsploit(provider="aws", authmethod="cli", profile='default', output_dir='output', global_settings={}):
    """
    Run CloudSploit audit tool for cloud providers.

    Args:
        provider (str, optional): The cloud provider to run CloudSploit on. Defaults to "aws".
        authmethod (str, optional): The authentication method to use. Defaults to "cli".
        profile (str, optional): The AWS profile/Azure subscription to use for authentication and auditing. Defaults to "default".

    Returns:
        None
    """
    cloudsploit_dir = os.path.abspath(os.path.join(os.getcwd(), "tools", "cloudsploit"))
    if not authenticate.check_logged_in_cli(provider):
        print(f"Not logged into {provider}")
        return

    if provider == "aws":
        if authmethod == "cli":
            credentials = authenticate.get_aws_credentials(profile)
            authenticate.create_cloudsploit_config(provider, credentials)
            
            cmds = [
                f"mkdir -p {output_dir}/cloudsploit/",
                f"/usr/bin/env node index.js --config {cloudsploit_dir}/config.js --csv {output_dir}/{profile}/cloudsploit/cloudsploit-output.csv --json {output_dir}/{profile}/cloudsploit/cloudsploit-output.json --console none --cloud aws"
                f'rm -f {cloudsploit_dir}/creds.json'
            ]
        else:
            cmds = [f"echo '{RED}Other authentication methods not supported yet{NC}'"]
        cmd = '; '.join(cmds)

    elif provider == "azure":
        if authmethod == "cli":
            credentials = authenticate.get_azure_credentials(profile)
            authenticate.create_cloudsploit_config(provider, credentials)
            
            # Check if temp_app_details already exist in global_settings
            if "temp_app_details" in global_settings and all(key in global_settings["temp_app_details"] for key in ["clientid", "clientsecret"]):
                temp_app_details = global_settings["temp_app_details"]
            else:
                # Create a temporary Azure app registration
                temp_app_details = create_temp_azure_app(credentials.get("subscription_id"))
                global_settings["temp_app_details"] = temp_app_details

            clientid = temp_app_details["clientid"]
            clientsecret = temp_app_details["clientsecret"]
            credentials.setdefault("application_id", clientid)
            credentials.setdefault("key_value", clientsecret)
            authenticate.create_cloudsploit_config(provider, credentials)
            
            cmds = [
                'trap "cleanup_temp_azure_app {}" EXIT'.format(clientid),  # Cleanup on exit
                f"mkdir -p {output_dir}/cloudsploit/",
                f"/usr/bin/env node index.js --config {cloudsploit_dir}/config.js --csv {output_dir}/{profile}/cloudsploit/cloudsploit-output.csv --json {output_dir}/{profile}/cloudsploit/cloudsploit-output.json --console none --cloud azure",
                f'rm -f {cloudsploit_dir}/creds.json'
            ]
            cmd = '; '.join(cmds)
        else:
            cmd = f"echo '{RED}Other authentication methods not supported yet{NC}'"


    print(f'Running CloudSploit with command: "{cmd}"')
    interrupted = run_commands([cmd, f'echo "{GREEN}{BOLD}CloudSploit run completed!"{NC}'], cloudsploit_dir, print_output=True)
    return interrupted


def run_monkey365(provider="azure", authmethod="cli", profile='default', output_dir='output', global_settings={}):
    """
    Run Monkey365 audit tool for cloud providers.

    Args:
        provider (str, optional): The cloud provider to run Monkey365 on. Defaults to "azure".
        authmethod (str, optional): The authentication method to use. Defaults to "cli".
        profile (str, optional): The Azure subscription to use for authentication and auditing. Defaults to "default".

    Returns:
        None
    """
    monkey365_dir = os.path.abspath(os.path.join(os.getcwd(), "tools", "monkey365"))
    if not authenticate.check_logged_in_cli(provider):
        print(f"Not logged into {provider}")
        return

    if provider == "azure":
        if authmethod == "cli":
            if "temp_app_details" in global_settings and all(key in global_settings["temp_app_details"] for key in ["clientid", "clientsecret"]):
                temp_app_details = global_settings["temp_app_details"]
            else:   
                credentials = authenticate.get_azure_credentials(profile)
                temp_app_details = create_temp_azure_app(credentials.get("subscription_id"))
                global_settings["temp_app_details"] = temp_app_details

            clientid = temp_app_details["clientid"]
            clientsecret = temp_app_details["clientsecret"]


            cmds = [
                f'pwsh -c "$ClientSecret = \'{clientsecret}\' | ConvertTo-SecureString -AsPlainText -Force; Import-Module ./monkey365.psm1; Invoke-Monkey365 -ClientId {clientid} -ClientSecret $ClientSecret -Instance Azure -Analysis All -subscriptions {credentials.get("subscription_id")} -TenantID {credentials.get("directory_id")} -ExportTo CLIXML,EXCEL,CSV,JSON,HTML -OutDir {output_dir}/{profile}/monkey365/"'
            ]
            cmd = '; '.join(cmds)

    print(f'Running Monkey365 with command: "{cmd}"')
    interrupted = run_commands([cmd, f'echo "{GREEN}{BOLD}Monkey365 run completed!"{NC}'], monkey365_dir, print_output=True)
    return interrupted






def user_questions():
    """
    Prompts the user with a series of questions to gather information about the cloud providers, authentication methods,
    profiles, and tools to be used for auditing.

    Returns:
        dict: A dictionary containing the user's answers.
    """
    providers_question = {
        'options': ['aws', 'azure'],
        'default_counters': [0, 0],
        'menu_text': 'Select the cloud providers to audit:',
        'print_results': False
    }
    authmethod_question = {
        'options': ['cli', 'config file (not supported yet)', 'environment variables (not supported yet)'],
        'default_counters': [1, 0, 0],
        'menu_text': 'Select the authentication method to use for: {}',
        'print_results': False
    }
    aws_tools_question = { 
        'options': ['Prowler', 'ScoutSuite', 'CloudFox', 'CloudSploit'],
        'default_counters': [1, 1, 1, 1],
        'menu_text': 'Select the tools to run for AWS',
        'print_results': False
    }    
    azure_tools_question = { 
        'options': ['Prowler', 'ScoutSuite', 'CloudFox', 'CloudSploit', 'Monkey365'],
        'default_counters': [1, 1, 1, 1, 1],
        'menu_text': 'Select the tools to run for Azure',
        'print_results': False
    }
    aws_profile_question = {
        'options': authenticate.list_aws_profiles(),
        'default_counters': [0]*len(authenticate.list_aws_profiles()),
        'menu_text': 'Select one AWS profile to use:',
        'print_results': False
    }
    azure_profile_question = {
        'options': authenticate.list_azure_profiles(),
        'default_counters': [0]*len(authenticate.list_azure_profiles()),
        'menu_text': 'Select one Azure profile to use:',
        'print_results': False
    }

    answers = {}
    provider_answers = selectionmenu.make_menu_selection(providers_question['options'], 
                                                         providers_question['default_counters'],
                                                         menu_text=providers_question['menu_text'], 
                                                         bool_input=True, return_as_str=True)

    for provider in provider_answers:
        answers[provider] = {}
        authmethod_answers = selectionmenu.make_menu_selection(authmethod_question['options'],
                                                               authmethod_question['default_counters'],
                                                               menu_text=authmethod_question['menu_text'].format(provider),
                                                               bool_input=True, return_as_str=True)
        
        # If AWS has profiles available besides the default, ask the user to select one
        if provider == 'aws' and 'cli' in authmethod_answers and aws_profile_question['options'] != ['default']:
            profile_answers = selectionmenu.make_menu_selection(aws_profile_question['options'],
                                                                aws_profile_question['default_counters'],
                                                                menu_text=aws_profile_question['menu_text'], 
                                                                bool_input=True, return_as_str=True)
                                                                
        # If Azure has more than one available subscription, ask the user to select one    
        elif provider == 'azure' and 'cli' in authmethod_answers:# and len(azure_profile_question['options']) > 1:
            profile_answers = selectionmenu.make_menu_selection(azure_profile_question['options'],
                                                                azure_profile_question['default_counters'],
                                                                menu_text=azure_profile_question['menu_text'], 
                                                                bool_input=True, return_as_str=True)
        else:
            profile_answers = 'default'

        if provider == 'aws':
            tools_questions = aws_tools_question
        elif provider == 'azure':
            tools_questions = azure_tools_question
        tools_answers = selectionmenu.make_menu_selection(tools_questions['options'], 
                                                          tools_questions['default_counters'],
                                                          menu_text=tools_questions['menu_text'].format(provider), 
                                                          bool_input=True, return_as_str=True)
        
        answers[provider] = {'authmethod': authmethod_answers, 'profile': profile_answers, 'tools': tools_answers}

    return answers



def run_tools(global_settings):
    """
    Run the selected tools for each provider based on the global settings.

    Args:
        global_settings (dict): A dictionary containing the global settings.

    Returns:
        bool: True if the execution was interrupted, False otherwise.
    """
    interrupted = False
    for provider, details in global_settings['answers'].items():
        authmethods = details['authmethod']
        tools = details['tools']
        profiles = details['profile']
        
        # create a directory to store the output of the tools, based on the current date and time
        output_dir = global_settings['base_output_dir'].format(provider)
        os.makedirs(output_dir, exist_ok=True)

        # Run the selected tools for the provider
        for authmethod in authmethods:
            for tool in tools:
                for profile in profiles:
                    if interrupted:
                        break
                    if tool == 'Prowler':
                        print(f'Running {tool} with {authmethod} for {provider}')
                        interrupted = run_prowler(provider, authmethod, profile, output_dir)
                    elif tool == 'ScoutSuite':
                        print(f'Running {tool} with {authmethod} for {provider}')
                        interrupted = run_scoutsuite(provider, authmethod, profile, output_dir)
                    elif tool == 'CloudFox':
                        print(f'Running {tool} with {authmethod} for {provider}')
                        interrupted = run_cloudfox(provider, authmethod, profile, output_dir)
                    elif tool == 'CloudSploit':
                        print(f'Running {tool} with {authmethod} for {provider}')
                        interrupted = run_cloudsploit(provider, authmethod, profile, output_dir, global_settings)
                    elif tool == 'Monkey365':
                        print(f'Running {tool} with {authmethod} for {provider}')
                        interrupted = run_monkey365(provider, authmethod, profile, output_dir, global_settings)
    return interrupted


def post_run_actions(global_settings, interrupted=False):
    """
    Perform post-run actions after the audit tools have finished running.

    Args:
        global_settings (dict): The global settings for the audit.
        interrupted (bool, optional): Indicates if the audit was interrupted. Defaults to False.
    """
    # Cleanup temporary Azure app registration if it was created
    if 'temp_app_details' in global_settings and 'clientid' in global_settings['temp_app_details']:
        print("Cleaning up temporary Azure app registration...")
        cleanup_temp_azure_app(global_settings['temp_app_details']['clientid'])
    
    # Analyze the output of the tools
    for provider, details in global_settings['answers'].items():
        output_dir = global_settings['base_output_dir'].format(provider)
    
        for tool in details['tools']:
            if tool == 'Prowler':
                analyze.summarize_prowler(output_dir, provider)
            elif tool == 'ScoutSuite':
                analyze.summarize_scoutsuite(output_dir, provider)
            elif tool == 'CloudFox':
                analyze.summarize_cloudfox(output_dir, provider)
            elif tool == 'CloudSploit':
                analyze.summarize_cloudsploit(output_dir, provider)
            elif tool == 'Monkey365':
                analyze.summarize_monkey365(output_dir, provider)

        # Categorize all detected issues
        analyze.categorize_all_tools_issues(output_dir, provider)

        # Run Prowler dashboard in the background
        print('Starting Prowler dashboard, use Ctrl+C to stop it...')
        prowler_dir = os.path.abspath(os.path.join(os.getcwd(), 'tools', 'prowler'))
        cmd = 'prowler dashboard'
        interrupted = run_commands([f'source {prowler_dir}/venv_prowler/bin/activate', cmd, 'deactivate', f"echo '{GREEN}{BOLD}Prowler dashboard completed!{NC}'"], f'{output_dir}/prowler', print_output=True)
    


def main():
    """
    Main function to start the cloud audit process.

    This function performs the following steps:
    1. Collects user input through a series of questions and stores the answers in a global settings dictionary.
    2. Executes the cloud auditing tools with the settings gathered.
    3. Performs post-run actions, such as generating the reports and cleaning up.
    """
    global_settings = {}
    global_settings['answers'] = user_questions()
    global_settings['base_output_dir'] = os.path.abspath(os.path.join(os.getcwd(), "output", '{}-' + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
    run_tools(global_settings)
    post_run_actions(global_settings, False)

if __name__ == "__main__":
    main()




