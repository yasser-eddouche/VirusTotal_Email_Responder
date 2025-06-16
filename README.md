# VirusTotal Email Responder

A Cortex responder that sends enhanced VirusTotal analysis results via email, including full case details, severity classification, and actionable information about potential threats.

## Description

The VirusTotal Email Responder integrates with Cortex and TheHive to automatically generate and send email notifications when VirusTotal analysis is performed on file hashes. The responder provides detailed analysis results with severity classification, file information, antivirus detections, and actionable recommendations.

## Features

- **Comprehensive Analysis Reports**: Detailed email reports with complete VirusTotal analysis results
- **Severity Classification**: Automatic categorization of threats (CRITICAL, HIGH, MEDIUM, LOW, CLEAN)
- **Case Integration**: Includes full case details from TheHive in the report
- **Detection Threshold**: Configurable malware detection threshold for severity classification
- **Selective Reporting**: Option to only send emails for files above a specified malware threshold
- **Fallback Mechanism**: Uses taxonomies when full reports aren't available
- **Configurable Email**: Support for standard SMTP servers or MailHog with configurable TLS

## Requirements

- Python 3.6+
- Cortex 3.x
- TheHive 5.x
- SMTP server or MailHog for email delivery
- Python packages listed in [`requirements.txt`](requirements.txt):
  - cortexutils
  - requests

## Installation

1. Clone this repository to your Cortex server's responders directory:

   ```
   cd /path/to/cortex/responders/
   git clone https://github.com/your-org/VirusTotalEmailResponder
   ```

2. Install the required dependencies:

   ```
   pip install -r VirusTotalEmailResponder/requirements.txt
   ```

3. Ensure the responder script has execute permissions:

   ```
   chmod +x VirusTotalEmailResponder/virustotal_email_responder.py
   ```

4. Restart Cortex to detect the new responder.

## Configuration

Configure the responder in Cortex UI with the following parameters:

| Parameter                 | Description                                    | Default                        |
| ------------------------- | ---------------------------------------------- | ------------------------------ |
| mailhog_host              | SMTP server hostname or IP address             | localhost                      |
| mailhog_port              | SMTP server port                               | 1025                           |
| smtp_username             | SMTP server username (optional)                |                                |
| smtp_password             | SMTP server password (optional)                |                                |
| use_tls                   | Enable TLS for SMTP connection                 | false                          |
| from_email                | Sender email address                           | security-alerts@yourdomain.com |
| to_email                  | Recipient email address(es) (comma-separated)  | soc-team@yourdomain.com        |
| malware_threshold         | Malware detection threshold percentage (0-100) | 50.0                           |
| only_send_above_threshold | Only send emails for files above threshold     | false                          |

## Usage

1. Configure the responder in Cortex
2. Enable the responder for your organization
3. Create an analyzer job in TheHive or Cortex using VirusTotal_GetReport_3_1
4. The responder will automatically trigger when the analyzer completes

## Example Email Output

The generated email includes:

- Severity classification with detection rate
- Complete case information from TheHive
- File metadata (name, hashes, type, size)
- Detection summary statistics
- Detailed antivirus results from major engines
- AI-based and sandbox verdicts (when available)
- Actionable recommendations based on threat level
- Direct link to VirusTotal report

## License

AGPL-V3
