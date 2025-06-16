#!/usr/bin/env python3

import requests
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import logging
from cortexutils.responder import Responder

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalEmailResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        
        # MailHog/SMTP configuration
        self.mailhog_host = self.get_param('config.mailhog_host', None, 'MailHog/SMTP host is missing')
        self.mailhog_port = self.get_param('config.mailhog_port', 1025, None)
        self.smtp_username = self.get_param('config.smtp_username', None, None)
        self.smtp_password = self.get_param('config.smtp_password', None, None)
        self.use_tls = self.get_param('config.use_tls', True, None)  # New: Toggle TLS
        
        # Email configuration
        self.from_email = self.get_param('config.from_email', 'fromthehive@local.com', None)
        self.to_email = self.get_param('config.to_email', None, 'Recipient email is missing')
        
        # Malware threshold percentage
        self.malware_threshold = self.get_param('config.malware_threshold', 50.0, None)
        
        # Only send emails for files above threshold
        self.only_send_above_threshold = self.get_param('config.only_send_above_threshold', False, None)

    def run(self):
        try:
            logger.info("Starting VirusTotalEmailResponder")
            # Get the job data
            job_id = self.get_param('data._id', None, 'Job ID is missing')
            
            # Check if this is related to VirusTotal_GetReport_3_1
            reports = self.get_param('data.reports', {})
            if 'VirusTotal_GetReport_3_1' not in reports:
                self.error('No VirusTotal_GetReport_3_1 report found in observable')

            # Get the analysis report or taxonomies
            report_data = self.get_param('data.reports.VirusTotal_GetReport_3_1', None, 'VirusTotal report data is missing')
            full_report = self.get_param('data.report', None)
            
            if not full_report and not report_data.get('taxonomies'):
                self.error('No valid report or taxonomies available')
            
            # Extract relevant information
            if full_report and 'attributes' in full_report:
                file_info = self.extract_file_info(full_report)
                malware_percentage = self.calculate_malware_percentage(full_report)
                analysis_stats = self.get_analysis_stats(full_report)
                threat_categories = self.get_threat_categories(full_report)
                selected_results = self.get_selected_results(full_report)
                crowdsourced_ai_results = full_report.get('attributes', {}).get('crowdsourced_ai_results', [])
                sandbox_verdicts = full_report.get('attributes', {}).get('sandbox_verdicts', {})
            else:
                # Fallback to taxonomies
                file_info = self.extract_file_info_fallback()
                malware_percentage, total_engines, malicious_count = self.calculate_malware_percentage_fallback(report_data.get('taxonomies', []))
                analysis_stats = {'malicious': malicious_count, 'total': total_engines, 'suspicious': 0, 'undetected': total_engines - malicious_count, 'harmless': 0, 'type_unsupported': 0}
                threat_categories = []
                selected_results = []
                crowdsourced_ai_results = []
                sandbox_verdicts = {}
                logger.warning("Using taxonomies fallback due to missing full report")

            # Check if we should send email based on threshold
            if self.only_send_above_threshold and malware_percentage < self.malware_threshold:
                self.report({'message': f'Malware percentage ({malware_percentage:.2f}%) below threshold ({self.malware_threshold}%). Email not sent.'})
                return
            
            # Get case information
            case_info = self.get_case_info()
            
            # Generate email content
            email_subject = self.generate_email_subject(file_info, malware_percentage, case_info)
            email_body = self.generate_email_body(file_info, malware_percentage, analysis_stats, threat_categories, selected_results, crowdsourced_ai_results, sandbox_verdicts, case_info)
            
            # Send email via MailHog/SMTP
            self.send_email(email_subject, email_body)
            self.report({
                'message': f'Email sent successfully for {file_info["filename"]} ({malware_percentage:.2f}% malware)',
                'malware_percentage': malware_percentage,
                'file_hash': file_info.get('sha256', 'N/A')
            })
            logger.info(f"Email sent successfully for {file_info['filename']}")
            
        except Exception as e:
            logger.error(f'Failed to process VirusTotal report: {str(e)}')
            self.error(f'Failed to process VirusTotal report: {str(e)}')

    def get_case_info(self):
        """Extract detailed case information from job data"""
        case_info = {}
        try:
            case_info['id'] = self.get_param('data.case._id', 'N/A')
            case_info['title'] = self.get_param('data.case.title', 'N/A')
            case_info['severity'] = self.get_param('data.case.severity', 'N/A')
            case_info['tlp'] = self.get_param('data.case.tlp', 'N/A')
            case_info['description'] = self.get_param('data.case.description', 'N/A')
            case_info['tags'] = self.get_param('data.case.tags', [])
            case_info['status'] = self.get_param('data.case.status', 'N/A')
            case_info['created_at'] = self.get_param('data.case.createdAt', 'N/A')
            case_info['owner'] = self.get_param('data.case.owner', 'N/A')
            observables = self.get_param('data.case.artifacts', [])
            case_info['observables'] = [
                {
                    'data': obs.get('data', 'N/A'),
                    'dataType': obs.get('dataType', 'N/A'),
                    'tlp': obs.get('tlp', 'N/A')
                } for obs in observables[:10]
            ]
            logger.info(f"Retrieved case info for case ID: {case_info['id']}")
        except Exception as e:
            logger.warning(f'Failed to retrieve case info: {str(e)}')
        return case_info

    def extract_file_info(self, report_data):
        """Extract file information from VirusTotal report"""
        file_info = {}
        attributes = report_data.get('attributes', {})
        
        file_info['sha256'] = attributes.get('sha256', 'N/A')
        file_info['md5'] = attributes.get('md5', 'N/A')
        file_info['sha1'] = attributes.get('sha1', 'N/A')
        file_info['filename'] = attributes.get('meaningful_name', attributes.get('names', ['Unknown'])[0])
        file_info['size'] = attributes.get('size', 0)
        file_info['file_type'] = attributes.get('type_description', 'Unknown')
        file_info['first_submission'] = datetime.fromtimestamp(attributes.get('first_submission_date', 0)).strftime('%Y-%m-%d %H:%M:%S') if attributes.get('first_submission_date') else 'N/A'
        file_info['last_analysis'] = datetime.fromtimestamp(attributes.get('last_analysis_date', 0)).strftime('%Y-%m-%d %H:%M:%S') if attributes.get('last_analysis_date') else 'N/A'
        
        logger.info(f"Extracted file info for SHA256: {file_info['sha256']}")
        return file_info

    def extract_file_info_fallback(self):
        """Extract file information from input data when full report is unavailable"""
        file_info = {}
        file_info['sha256'] = self.get_param('data.data', 'N/A')
        file_info['md5'] = 'N/A'
        file_info['sha1'] = 'N/A'
        file_info['filename'] = self.get_param('data.message', 'Unknown').split('hash of ')[-1] if 'hash of' in self.get_param('data.message', '') else 'Unknown'
        file_info['size'] = 0
        file_info['file_type'] = 'Unknown'
        file_info['first_submission'] = 'N/A'
        file_info['last_analysis'] = 'N/A'
        logger.info(f"Extracted fallback file info for SHA256: {file_info['sha256']}")
        return file_info

    def calculate_malware_percentage(self, report_data):
        """Calculate malware percentage from VirusTotal results"""
        attributes = report_data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        total_engines = stats.get('malicious', 0) + stats.get('undetected', 0) + stats.get('harmless', 0) + stats.get('suspicious', 0)
        malicious_count = stats.get('malicious', 0)
        
        if total_engines > 0:
            percentage = (malicious_count / total_engines) * 100.0
            logger.info(f"Calculated malware percentage: {percentage:.2f}%")
            return percentage
        logger.info("No engines available, returning 0%")
        return 0.0

    def calculate_malware_percentage_fallback(self, taxonomies):
        """Calculate malware percentage from taxonomies"""
        for taxonomy in taxonomies:
            if taxonomy.get('namespace') == 'VT' and taxonomy.get('predicate') == 'GetReport' and '/' in taxonomy.get('value', ''):
                try:
                    malicious, total = map(int, taxonomy['value'].split('/'))
                    if total > 0:
                        percentage = (malicious / total) * 100.0
                        logger.info(f"Calculated fallback malware percentage: {percentage:.2f}%")
                        return percentage, total, malicious
                except ValueError:
                    pass
        logger.info("No valid taxonomy data, returning 0%")
        return 0.0, 0, 0

    def get_analysis_stats(self, report_data):
        """Get detailed analysis statistics"""
        stats = {
            'malicious': 0,
            'suspicious': 0,
            'undetected': 0,
            'harmless': 0,
            'type_unsupported': 0,
            'total': 0
        }
        
        attributes = report_data.get('attributes', {})
        analysis_stats = attributes.get('last_analysis_stats', {})
        
        stats['malicious'] = analysis_stats.get('malicious', 0)
        stats['suspicious'] = analysis_stats.get('suspicious', 0)
        stats['undetected'] = analysis_stats.get('undetected', 0)
        stats['harmless'] = analysis_stats.get('harmless', 0)
        stats['type_unsupported'] = analysis_stats.get('type-unsupported', 0)
        stats['total'] = stats['malicious'] + stats['suspicious'] + stats['undetected'] + stats['harmless']
        
        return stats

    def get_threat_categories(self, report_data):
        """Extract threat categories if available"""
        categories = []
        attributes = report_data.get('attributes', {})
        tags = attributes.get('tags', [])
        
        for tag in tags:
            categories.append(tag)
        
        return categories

    def get_selected_results(self, report_data, max_results=10):
        """Extract selected antivirus results"""
        results = []
        priority_engines = ['Microsoft', 'Kaspersky', 'Malwarebytes', 'Symantec', 'McAfee', 'TrendMicro', 'ESET', 'Avast', 'AVG', 'CrowdStrike']
        
        for engine in sorted(priority_engines):
            scan_result = report_data.get('attributes', {}).get('last_analysis_results', {}).get(engine, {})
            if scan_result and len(results) < max_results:
                if scan_result.get('category') in ['malicious', 'suspicious']:
                    results.append(f"{engine}: {scan_result.get('result', 'Detected')}")
                else:
                    results.append(f"{engine}: Clean")

        for engine, scan_result in report_data.get('attributes', {}).get('last_analysis_results', {}).items():
            if engine not in priority_engines and len(results) < max_results:
                if scan_result.get('category') in ['malicious', 'suspicious']:
                    results.append(f"{engine}: {scan_result.get('result', '')}")
        
        return results

    def get_severity_level(self, malware_percentage):
        """Determine severity level based on malware percentage"""
        if malware_percentage >= 75:
            return "🔴 CRITICAL"
        elif malware_percentage >= 50:
            return "🟠 HIGH"
        elif malware_percentage >= 25:
            return "🟡 MEDIUM"
        elif malware_percentage > 0:
            return "🔵 LOW"
        else:
            return "🟢 CLEAN"

    def generate_email_subject(self, file_info, malware_percentage, case_info):
        """Generate email subject line"""
        severity = self.get_severity_level(malware_percentage)
        case_id = case_info.get('id')
        
        if case_id != 'N/A':
            return f"[Case {case_id}] {severity}: VirusTotal Analysis for {file_info.get('filename', 'Unknown')} ({malware_percentage:.1f}%)"
        else:
            return f"{severity}: VirusTotal Analysis for {file_info.get('filename', 'Unknown')} ({malware_percentage:.1f}%)"

    def generate_email_body(self, file_info, malware_percentage, analysis_stats, threat_categories, selected_results, crowdsourced_ai_results, sandbox_verdicts, case_info):
        """Generate the email body content with full case information"""
        permalink = f"https://www.virustotal.com/gui/file/{file_info.get('sha256', 'N/A')}"
        severity = self.get_severity_level(malware_percentage)
        
        email_body = f"""🛡️ VIRUSTOTAL ANALYSIS REPORT
{'=' * 50}

SEVERITY: {severity}
Detection Rate: {malware_percentage:.2f}% ({analysis_stats.get('malicious', 0)}/{analysis_stats.get('total', 0)} engines)

CASE INFORMATION:
- Case ID: {case_info.get('id', 'N/A')}
- Title: {case_info.get('title', 'N/A')}
- Severity: {case_info.get('severity', 'N/A')}
- TLP: {case_info.get('tlp', 'N/A')}
- Status: {case_info.get('status', 'N/A')}
- Created At: {case_info.get('created_at', 'N/A')}
- Owner: {case_info.get('owner', 'N/A')}
- Description: {case_info.get('description', 'N/A')[:500]}{'...' if len(case_info.get('description', '')) > 500 else ''}
- Tags: {', '.join(case_info.get('tags', [])) or 'None'}

OBSERVABLES:
"""
        if case_info.get('observables'):
            for obs in case_info.get('observables', []):
                email_body += f"- {obs['dataType']}: {obs['data']} (TLP: {obs['tlp']})\n"
        else:
            email_body += "- No observables available\n\n"

        email_body += f"""FILE INFORMATION:
- Name: {file_info.get('filename', 'N/A')}
- Type: {file_info.get('file_type', 'N/A')}
- Size: {file_info.get('size', 0):,} bytes
- SHA256: {file_info.get('sha256', 'N/A')}
- MD5: {file_info.get('md5', 'N/A')}
- SHA1: {file_info.get('sha1', 'N/A')}
- First Submission: {file_info.get('first_submission', 'N/A')}
- Last Analysis: {file_info.get('last_analysis', 'N/A')}

DETECTION SUMMARY:
- Malicious: {analysis_stats.get('malicious', 0)}
- Suspicious: {analysis_stats.get('suspicious', 0)}
- Undetected: {analysis_stats.get('undetected', 0)}
- Harmless: {analysis_stats.get('harmless', 0)}
- Type Unsupported: {analysis_stats.get('type_unsupported', 0)}
- Total Engines: {analysis_stats.get('total', 0)}

"""

        if threat_categories:
            email_body += "THREAT CATEGORIES:\n"
            for category in threat_categories:
                email_body += f"- {category}\n"
            email_body += "\n"

        email_body += "VIRUS TOTAL REPORT SUMMARY:\n"
        email_body += f"- Total Scans: {analysis_stats.get('total', 0)}\n"
        email_body += f"- Malicious Detections: {analysis_stats.get('malicious', 0)}\n"
        email_body += f"- Suspicious Detections: {analysis_stats.get('suspicious', 0)}\n"
        email_body += f"- Undetected: {analysis_stats.get('undetected', 0)}\n"
        email_body += f"- Harmless: {analysis_stats.get('harmless', 0)}\n"
        email_body += f"- Type Unsupported: {analysis_stats.get('type_unsupported', 0)}\n"

        if selected_results:
            email_body += "\nANTIVIRUS RESULTS:\n"
            for result in sorted(selected_results):
                email_body += f"- {result}\n"
        else:
            email_body += "\nANTIVIRUS RESULTS:\n- No detailed results available\n"

        if crowdsourced_ai_results:
            email_body += "\nCROWDSOURCED AI VERDICTS:\n"
            for ai_result in sorted(crowdsourced_ai_results, key=lambda x: x.get('source', '')):
                email_body += f"- Source: {ai_result.get('source', 'N/A')}\n"
                email_body += f"  Verdict: {ai_result.get('verdict', 'N/A')}\n"
                if ai_result.get('analysis'):
                    email_body += f"  Analysis: {ai_result.get('analysis', '')[:200]}{'...' if len(ai_result.get('analysis', '')) > 200 else ''}\n"

        if sandbox_verdicts:
            email_body += "\nSANDBOX VERDICTS:\n"
            for sandbox in sorted(sandbox_verdicts.keys()):
                verdict = sandbox_verdicts.get(sandbox, {})
                email_body += f"- {sandbox}: {verdict.get('category', 'N/A')} (Confidence: {verdict.get('confidence', 'N/A')}%)\n"

        email_body += f"\nRECOMMENDATIONS:\n"
        if malware_percentage >= 50:
            email_body += "- 🚨 HIGH RISK: Quarantine this file immediately\n"
            email_body += "- Block file hash on security controls\n"
            email_body += "- Investigate potential compromise\n"
        elif malware_percentage > 0:
            email_body += "- ⚠️ CAUTION: Verify file before execution\n"
            email_body += "- Consider additional analysis\n"
        else:
            email_body += "- ✅ File appears clean\n"

        email_body += f"\nVIRUSTOTAL LINK:\n{permalink}\n"
        email_body += f"\nReport generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        email_body += "Analyzer: VirusTotal_GetReport_3_1\n"
        
        logger.info("Generated email body successfully")
        return email_body

    def send_email(self, subject, body):
        """Send email via SMTP with configurable TLS support"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = self.to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            logger.info(f"Connecting to SMTP server: {self.mailhog_host}:{self.mailhog_port} (TLS: {self.use_tls})")
            server = smtplib.SMTP(self.mailhog_host, self.mailhog_port)
            
            # Use TLS only if enabled and not using MailHog's default port (1025)
            if self.use_tls and self.mailhog_port != 1025:
                logger.debug("Enabling STARTTLS")
                server.starttls()
            
            # Authenticate if credentials are provided
            if self.smtp_username and self.smtp_password:
                logger.debug(f"Authenticating with username: {self.smtp_username}")
                server.login(self.smtp_username, self.smtp_password)
            
            text = msg.as_string()
            server.sendmail(self.from_email, self.to_email, text)
            server.quit()
            logger.info(f"Email sent to {self.to_email}")
        except Exception as e:
            if 'server' in locals():
                server.quit()
            logger.error(f"Failed to send email: {str(e)}")
            raise

if __name__ == '__main__':
    VirusTotalEmailResponder().run()