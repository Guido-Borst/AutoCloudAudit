#! /bin/bash

# Copyright (c) 2024 Guido Borst
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

az --version
az extension add --name account
az extension add --name healthcareapis
# az provider register --namespace 'Microsoft.HealthcareApis'
# az provider show --namespace Microsoft.HealthcareApis --query "resourceTypes[?resourceType=='services'].locations"


echo "Creating app registration"
read -p "Press enter to continue or Ctrl+C to cancel"

### Define app registration name, etc.
appregname=AutoCloudAudit_temp_App
clientid=$(az ad app create --display-name $appregname --query appId --output tsv)
echo "Client/App ID: $clientid"
objectid=$(az ad app show --id $clientid --query id --output tsv)
echo "Object ID: $objectid"

# wait for user input
echo "App registration created, now adding client secret"
read -p "Press enter to continue or Ctrl+C to cancel"

# ###Remove api permissions: disable default exposed scope first
# default_scope=$(az ad app show --id $clientid | jq '.oauth2Permissions[0].isEnabled = false' | jq -r '.oauth2Permissions')
# echo "Default scope: $default_scope"
# az ad app update --id $clientid --set oauth2Permissions="$default_scope"
# az ad app update --id $clientid --set oauth2Permissions="[]"

# echo "API permissions removed, now adding new client secret"
# read -p "Press enter to continue or Ctrl+C to cancel"

###Add client secret with expiration. The default is one year.
clientsecretname=AutoCloudAudit_ScriptGenerated
enddate=$(date -d "+1 year" +%Y-%m-%d)
clientsecret=$(az ad app credential reset --id $clientid --append --display-name $clientsecretname --end-date $enddate --query password --output tsv)
echo $clientsecret


# wait for user input
echo "Client secret created, now setting up service principal"
read -p "Press enter to continue or Ctrl+C to cancel"


###Create an AAD service principal
spid=$(az ad sp create --id $clientid --query id --output tsv)
echo "Service principal ID after creation: $spid"
###Look up a service principal
spid=$(az ad sp show --id $clientid --query id --output tsv)
echo "Service principal ID after lookip (should be the same): $spid"
echo "Done"


# To delete, run: az ad app delete --id $clientid