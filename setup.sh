#!/bin/bash

# Copyright (c) 2024 Guido Borst
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
VERBOSE=0

while (( "$#" )); do
  case "$1" in
    --verbose)
      VERBOSE=1
      shift
      ;;
    *) 
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Check if pip is installed and then install required packages
function setup_pip() {
    pip_path=$(which pip || which pip3)
    if [ -z "$pip_path" ]; then
        echo "pip or pip3 is not installed. Installing..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
            python3 get-pip.py
            pip_path=$(which pip || which pip3) # Update pip_path after installation
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            sudo apt install python3-pip
            pip_path=$(which pip || which pip3) # Update pip_path after installation
        else
            echo "Unsupported operating system"
            exit 1
        fi
    else
        echo "Using pip: $pip_path"
    fi

    # Install needed packages using pip
    if [ ! -z "$pip_path" ]; then
        echo "Installing packages..."
        $pip_path install requests
        $pip_path install pandas
        $pip_path install prettytable
        $pip_path install wheel
    fi
}

# Setup main virtual environment
function setup_venv() {
    venv_dir=".venv"
    # Check if the virtual environment directory exists and can be activated
    if [ -d "$venv_dir" ]; then
        echo 'Checking existing virtual environment...'
        # Try to activate the virtual environment
        source $venv_dir/bin/activate 2>/dev/null
        if [ $? -eq 0 ]; then
            # Check if Python is available in the virtual environment
            python --version >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}A working virtual environment found. Skipping creation.${NC}"
                return 0
            else
                echo 'Python not found in the virtual environment. Re-creating...'
                rm -rf $venv_dir
            fi
        else
            echo 'Failed to activate the virtual environment. Re-creating...'
            rm -rf $venv_dir
        fi
    fi

    # Create a new virtual environment
    pyver=$(which python3)
    echo 'Creating a new main virtual environment...'
    virtualenv -p $pyver $venv_dir
    if [ $? -eq 0 ]; then
        source $venv_dir/bin/activate
        python_version=$(python --version 2>&1)
        echo -e "${GREEN}Main virtual environment created with Python: $python_version${NC}"
    else
        echo -e "${RED}Failed to create virtual environment${NC}"
    fi
}

# Install Prowler
function install_prowler() {
    prowler_dir="tools/prowler"
    venv_dir="$prowler_dir/venv_prowler"
    mkdir -p $prowler_dir

    if [ -d "$venv_dir" ]; then
        source $venv_dir/bin/activate
        prowler_version=$(prowler --version 2>/dev/null)
        deactivate
    fi

    if [ -z "$prowler_version" ]; then
        echo 'Prowler is not installed in the virtual environment, installing...'
        virtualenv -p python3.11 $venv_dir
        source $venv_dir/bin/activate
        echo "Installing prowler, this can take some time"
        if [ $VERBOSE -eq 1 ]; then
            pip3 install --upgrade pip setuptools wheel
            pip install prowler
        else
            pip3 install --upgrade pip setuptools wheel > /dev/null 2>&1
            pip install prowler > /dev/null 2>&1
        fi
        prowler_version=$(prowler --version)
        echo -e "${GREEN}Prowler installed, version: $prowler_version${NC}"
        deactivate
    else
        echo -e "${GREEN}Prowler is already installed in the virtual environment, version: $prowler_version${NC}"
    fi
}

# Install ScoutSuite
function install_scoutsuite() {
    scoutsuite_dir="tools/scoutsuite"
    venv_dir="$scoutsuite_dir/venv_scoutsuite"
    mkdir -p $scoutsuite_dir

    if [ -d "$venv_dir" ]; then
        source $venv_dir/bin/activate
        scoutsuite_version=$(scout --version 2>/dev/null)
        deactivate
    fi

    if [ -z "$scoutsuite_version" ]; then
        echo 'ScoutSuite is not installed in the virtual environment, installing...'
        virtualenv -p python3 $venv_dir
        source $venv_dir/bin/activate
        echo "Installing ScoutSuite, this can take some time"
        if [ $VERBOSE -eq 1 ]; then
            pip3 install --upgrade pip setuptools wheel
            pip install scoutsuite
        else
            pip3 install --upgrade pip setuptools wheel > /dev/null 2>&1
            pip install scoutsuite > /dev/null 2>&1
        fi
        scoutsuite_version=$(scout --version)
        echo -e "${GREEN}ScoutSuite installed, version: $scoutsuite_version${NC}"
        deactivate
    else
        echo -e "${GREEN}ScoutSuite is already installed in the virtual environment, version: $scoutsuite_version${NC}"
    fi
}

# Install CloudFox
function install_cloudfox() {
    cloudfox_dir="tools/cloudfox"
    mkdir -p $cloudfox_dir

    if [ -x "$cloudfox_dir/cloudfox" ]; then
        cloudfox_version=$($cloudfox_dir/cloudfox --version)
        echo -e "${GREEN}CloudFox is already installed, version: $cloudfox_version${NC}"
        return
    fi

    OS=$(uname | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    if [ "$ARCH" = "x86_64" ]; then
        ARCH="amd64"
    elif [ "$ARCH" = "aarch64" ]; then
        ARCH="arm64"
    fi

    if [ "$OS" = "darwin" ]; then
        OS="macos"
        echo "Installing jq and wget via brew"
        brew install jq wget
    elif [ "$OS" = "linux" ]; then
        OS="linux"
    elif [ "$OS" = "msys" ] || [ "$OS" = "mingw" ] || [ "$OS" = "cygwin" ]; then
        OS="windows"
    else
        echo "Unsupported OS: $OS"
        exit 1
    fi

    latest_release=$(curl --silent "https://api.github.com/repos/BishopFox/cloudfox/releases/latest" | jq -r ".assets[] | select(.name | test(\"cloudfox-$OS-$ARCH.zip\")) | .browser_download_url")

    if [ -z "$latest_release" ]; then
        echo "No precompiled binary available for $OS-$ARCH, installing from source"
        go install github.com/BishopFox/cloudfox@latest
    else
        echo "Downloading CloudFox from $latest_release"
        wget $latest_release -O $cloudfox_dir/cloudfox.zip

        unzip $cloudfox_dir/cloudfox.zip -d "tools"
        rm $cloudfox_dir/cloudfox.zip
    fi
}

# Install CloudSploit
function install_cloudsploit() {
    cloudsploit_dir="tools/cloudsploit"

    if [ -x "$cloudsploit_dir/index.js" ]; then
        echo -e "${GREEN}CloudSploit is already installed${NC}"
        return
    fi

    # Check if NVM is installed
    if type nvm &> /dev/null; then
        echo -e "${YELLOW}NVM is already installed${NC}"
    else
        # install NVM (Node Version Manager)
        curl -s -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
    fi

    # Check if Node.js version 20 is installed
    if nvm ls 20 &> /dev/null; then
        echo -e "${YELLOW}Node.js version 20 is already installed${NC}"
    else
        # download and install Node.js
        nvm install 20
    fi

    echo "Using node $(which node) version $(node -v)" # should print `v20.12.2`
    echo "Using npm $(which npm) version $(npm -v)" # should print `10.5.0`

    mkdir -p $cloudsploit_dir
    git clone https://github.com/aquasecurity/cloudsploit.git $cloudsploit_dir
    cd $cloudsploit_dir
    npm install
    chmod +x index.js
    cp config_example.js config.js
    # Modify the credential_file line in config.js
    sed -i "s|// credential_file: '/path/to/file.json',|credential_file: './creds.json',|g" config.js
    mkdir -p output
    ./index.js -h
    cd ../..
}

# Install Monkey365
function install_monkey365() {
    monkey365_dir="tools/monkey365"

    if [ -f "$monkey365_dir/Invoke-Monkey365.ps1" ]; then
        echo -e "${GREEN}Monkey365 is already installed${NC}"
        return
    fi

    mkdir -p $monkey365_dir
    git clone https://github.com/silverhack/monkey365.git $monkey365_dir
}


# Main function
function main() {
    setup_pip
    setup_venv
    install_prowler
    install_scoutsuite
    install_cloudfox
    install_cloudsploit
    install_monkey365
}

main