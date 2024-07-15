# AutoCloudAudit

AutoCloudAudit is an open-source project designed to streamline cloud security assessments. It combines multiple existing open-source tools to help security experts evaluate cloud environments more efficiently. This tool supports both Amazon Web Services (AWS) and Microsoft Azure, and aims to provide a comprehensive overview of cloud infrastructure, highlighting security issues and enabling easy comparison of results across different tools. To further speed up the assessment process, AutoCloudAudit categorizes the detected security issues.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Efficiency**: Save time in performing cloud security assessments.
- **Setup Script**: Automates the installation and configuration of necessary tools.
- **User-Friendly Interface**: Simplifies the process of running security scans and interpreting results.
- **Multiple Tool Integration**: Combines the capabilities of several open-source security tools.
- **Result Summarization**: Provides a summary of findings from each tool.
- **Issue Categorization**: Categorizes all detected security issues for easier analysis.
- **AWS and Azure Compatibility**: Support the two largest cloud service providers.
- **Independent Risk Mapping**: Map security postures to multiple risk assessment frameworks independently.
- **Comprehensive Infrastructure Overview**: Provide a detailed overview of the cloud infrastructure. 


## Requirements

To successfully install and run all the tools included in this project, ensure the following requirements are met:

### General Requirements

- **Python 3**: The main script requires Python 3. Although AutoCloudAudit is developed with Python 3.11.6, it should work on most recent versions.

### Linux Specific Requirements

The following packages need to be installed on Linux systems:

- Curl
- Virtualenv
- Wget
- Jq
- Go/Golang
- Unzip
- Git

### macOS Specific Requirements

For macOS systems, the Brew package manager needs to be installed as it will be used to fetch some of the requirements dynamically.

### Recommended Linux Distribution

Opting for a Linux distribution like Kali Linux ensures that the majority of these requirements are pre-installed. Otherwise, missing packages can be added via the distribution’s package manager.

### AWS Permissions

To maximize the utility of all tools on AWS, the following roles are required:

- **SecurityAudit**: Required for all tools.
- **ViewOnlyAccess**: Required for Prowler.
- **ReadOnlyAccess**: Required for ScoutSuite.
- **CloudSploitSupplemental**: Required for CloudSploit.
- **AllowMoreReadForCloudFox190**: Required for CloudFox (though CloudFox can also run with the ViewOnlyAccess role with some checks failing, or with ReadOnlyAccess).


## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Guido-Borst/AutoCloudAudit.git
   cd AutoCloudAudit
   ```

2. Run the setup script:
   ```bash
   ./setup.sh
   ```

## Usage
1. To perform a cloud security scan, run the main script:
   ```bash
   python3 autocloudaudit.py
   ```

2. Follow the on-screen instructions to configure and start the assessment.

## Compatibility
- **Operating Systems**: Primarily developed for Linux systems but also supports macOS.
- **Cloud Providers**: AWS and Azure (extensible to other providers like GCP, Alibaba Cloud, and Kubernetes clusters).


## Future Improvements
While AutoCloudAudit provides a robust foundation for cloud security assessments, there are several areas where future enhancements could be made to further its capabilities:

1. **Integration of Additional Tools**:
   - **[ROADrecon](https://github.com/dirkjanm/ROADtools) and [BloodHound](https://github.com/SpecterOps/BloodHound)**: One of the project goals was to include tools that provide insights into the hierarchical structure of users and groups in the cloud environment, mapping out possible attack paths. Integrating ROADrecon and BloodHound would offer these insights, significantly enhancing the effectiveness of cloud assessments.

2. **Support for Additional Authentication Methods**:
   - Currently, the project only supports authentication via AWS-CLI and Azure-CLI. Adding support for other authentication methods, such as passing credentials via config files or environmental variables, would make the tool more versatile. The project structure already considers additional authentication methods, so implementing this should be straightforward.

3. **Support for Additional Cloud Platforms**:
   - At present, AutoCloudAudit supports only AWS and Azure cloud platforms. Extending support to Google Cloud Platform (GCP) would expand the use-cases and make the project beneficial to a wider audience.

4. **Comprehensive Mapping of Security Checks**:
   - It is important to map additional security checks to the existing categories. Fully mapping all Azure checks would streamline the review process. This would reduce the time required to review all findings and improve overall security assessment efficiency. Currently only AWS checks are mapped.



## Contributing
Contributions are welcome! If you have ideas for improvements or new features, including implementations from the [Future Improvements](#future-improvements) section above, please fork the repository, make your changes, and create a pull request. For major changes, open an issue first to discuss what you would like to change.



## Credits
AutoCloudAudit leverages the capabilities of the following open-source tools:
- **Prowler**: [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
- **ScoutSuite**: [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- **CloudSploit**: [aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit)
- **CloudFox**: [BishopFox/cloudfox](https://github.com/BishopFox/cloudfox)
- **Monkey365**: [silverhack/monkey365](https://github.com/silverhack/monkey365)

A special thanks to the authors of these tools for their hard work and contributions to the open-source community. 

Special thanks to [Computest](https://www.computest.nl/en/) for providing the opportunity to work on this project.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Each tool integrated by AutoCloudAudit is licensed under its respective license:
- **Prowler**: Apache-2.0 License
- **ScoutSuite**: GPL-2.0 License
- **CloudSploit**: GPL-3.0 License
- **CloudFox**: MIT License
- **Monkey365**: Apache-2.0 License

Please refer to the individual repositories for more details on their licensing.

