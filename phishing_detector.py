#!/usr/bin/env python3

"""
Advanced Phishing Message Detection Script
----------------------------------------
This script analyzes messages for potential phishing attempts using multiple detection methods:
- URL analysis
- Suspicious keyword detection
- Email header analysis
- Risk scoring system

Author: Security Team
Version: 1.0
"""

import re
import urllib.parse
import socket
from typing import List, Dict, Tuple
from email.parser import Parser
from collections import defaultdict
import ssl
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class PhishingDetector:
    def __init__(self):
        # Common phishing keywords and patterns
        self.suspicious_keywords = {
            # General phishing patterns
            'urgent': 0.3,
            'account suspended': 0.4,
            'verify your account': 0.4,
            'login attempt': 0.3,
            'unusual activity': 0.3,
            'password expired': 0.4,
            'security alert': 0.3,
            'click here': 0.2,
            'confirm identity': 0.4,
            'unusual login': 0.3,
            'limited time': 0.2,
            'account closure': 0.4,
            'suspicious activity': 0.4,
            
            # Fiverr-specific patterns
            'external payment': 0.8,
            'paypal only': 0.7,
            'western union': 0.8,
            'direct payment': 0.7,
            'contact outside': 0.6,
            'whatsapp': 0.5,
            'telegram': 0.5,
            'bonus offer': 0.4,
            'special promotion': 0.4,
            'fiverr support team': 0.5,
            'account verification required': 0.6,
            'order completed': 0.4,
            'payment pending': 0.4,
            'urgent payment': 0.6,
            'refund processing': 0.5,
            'additional fee': 0.5,
            'cryptocurrency': 0.7,
            'bitcoin payment': 0.8,
            'private email': 0.6,
            'skype chat': 0.5
        }
        
        # Suspicious TLD patterns
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs often used in phishing
            '.zip', '.review', '.country', '.kim', '.science',
            '.work', '.party', '.gdn', '.stream', '.download'
        ]
        
        # Suspicious sender patterns
        self.suspicious_sender_patterns = [
            # General patterns
            r'^\d+@',  # Starts with numbers
            r'[a-zA-Z0-9]+\d{4,}@',  # Contains 4 or more consecutive numbers
            r'security[_-]?alert',
            r'account[_-]?verify',
            r'support[_-]?\d+',
            
            # Fiverr-specific patterns
            r'fiverr[._-]?support\d*@',
            r'fiverr[._-]?security@',
            r'fiverr[._-]?payment@',
            r'fiverr[._-]?verify@',
            r'fiverr[._-]?team@',
            r'admin[._-]?fiverr@',
            r'support[._-]?team[._-]?\d*@',
            r'verification[._-]?team@',
            r'payment[._-]?support@',
            r'account[._-]?security@'
        ]

    def analyze_urls(self, text: str) -> List[Dict]:
        """
        Analyze URLs found in the text for suspicious patterns.
        """
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        results = []
        
        for url in urls:
            risk_score = 0
            reasons = []
            
            parsed_url = urllib.parse.urlparse(url)
            
            # Check for suspicious TLDs
            domain = parsed_url.netloc.lower()
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    risk_score += 0.4
                    reasons.append(f"Suspicious TLD: {tld}")
            
            # Check for IP addresses instead of domain names
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed_url.netloc):
                risk_score += 0.5
                reasons.append("IP address used instead of domain name")
            
            # Check for deceptive subdomains
            if parsed_url.netloc.count('.') > 2:
                risk_score += 0.3
                reasons.append("Multiple subdomains detected")
            
            # Check for URL encoding tricks
            if '%' in url:
                risk_score += 0.3
                reasons.append("URL contains encoded characters")
            
            results.append({
                'url': url,
                'risk_score': risk_score,
                'reasons': reasons
            })
            
        return results

    def analyze_keywords(self, text: str) -> Tuple[float, List[str]]:
        """
        Analyze text for suspicious keywords and phrases.
        """
        text = text.lower()
        total_score = 0
        detected_keywords = []
        
        for keyword, score in self.suspicious_keywords.items():
            if keyword in text:
                total_score += score
                detected_keywords.append(keyword)
        
        return total_score, detected_keywords

    def analyze_headers(self, headers: Dict) -> Tuple[float, List[str]]:
        """
        Analyze email headers for suspicious patterns.
        """
        score = 0
        reasons = []
        
        # Check Reply-To mismatch
        if 'from' in headers and 'reply-to' in headers:
            from_domain = headers['from'].split('@')[-1]
            reply_domain = headers['reply-to'].split('@')[-1]
            if from_domain != reply_domain:
                score += 0.4
                reasons.append("Reply-To domain mismatch")
        
        # Check for suspicious sender patterns
        if 'from' in headers:
            for pattern in self.suspicious_sender_patterns:
                if re.search(pattern, headers['from'], re.I):
                    score += 0.3
                    reasons.append(f"Suspicious sender pattern: {pattern}")
        
        # Check for missing or suspicious headers
        important_headers = ['received', 'authentication-results', 'dkim-signature']
        for header in important_headers:
            if header not in headers:
                score += 0.2
                reasons.append(f"Missing important header: {header}")
        
        return score, reasons

    def analyze_message(self, message_text: str, headers: Dict = None) -> Dict:
        """
        Perform complete analysis of a message.
        """
        total_score = 0
        analysis_results = {
            'overall_risk_score': 0,
            'risk_level': '',
            'url_analysis': [],
            'keyword_analysis': [],
            'header_analysis': [],
            'recommendations': []
        }
        
        # Analyze URLs
        url_results = self.analyze_urls(message_text)
        analysis_results['url_analysis'] = url_results
        url_score = sum(result['risk_score'] for result in url_results)
        total_score += url_score
        
        # Analyze keywords
        keyword_score, detected_keywords = self.analyze_keywords(message_text)
        analysis_results['keyword_analysis'] = {
            'score': keyword_score,
            'detected_keywords': detected_keywords
        }
        total_score += keyword_score
        
        # Analyze headers if provided
        if headers:
            header_score, header_reasons = self.analyze_headers(headers)
            analysis_results['header_analysis'] = {
                'score': header_score,
                'reasons': header_reasons
            }
            total_score += header_score
        
        # Calculate final risk score and level
        analysis_results['overall_risk_score'] = min(total_score, 1.0)
        
        if analysis_results['overall_risk_score'] >= 0.7:
            analysis_results['risk_level'] = 'High'
            analysis_results['recommendations'].append("Block this message immediately")
        elif analysis_results['overall_risk_score'] >= 0.4:
            analysis_results['risk_level'] = 'Medium'
            analysis_results['recommendations'].append("Review message carefully before taking any action")
        else:
            analysis_results['risk_level'] = 'Low'
            analysis_results['recommendations'].append("Message appears to be legitimate but always exercise caution")
        
        return analysis_results

def main():
    """
    Example usage of the PhishingDetector class.
    """
    # Example message for testing
    test_message = """
    URGENT: Fiverr Payment Issue Detected!
    
    Dear Seller,
    
    We have detected an issue with your recent payment. To prevent any delays, please verify your account immediately
    by clicking here: http://fiverr-secure-payments.tk/verify
    
    Additionally, you can expedite the process by contacting our support team on WhatsApp: +1234567890
    or make a direct payment through our secure Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    
    If you don't confirm within 24 hours, your pending payments will be cancelled.
    
    Best regards,
    Fiverr Support Team
    """
    
    # Example headers
    test_headers = {
        'from': 'fiverr-support-team@fiverr-secure-payments.tk',
        'reply-to': 'support-team@payment-verify.ml',
        'subject': 'Urgent: Fiverr Payment Verification Required'
    }
    
    # Create detector instance
    detector = PhishingDetector()
    
    # Analyze message
    results = detector.analyze_message(test_message, test_headers)
    
    # Print results
    print("\nPhishing Detection Results:")
    print("-" * 50)
    print(f"Risk Level: {results['risk_level']}")
    print(f"Overall Risk Score: {results['overall_risk_score']:.2f}")
    print("\nDetected Keywords:")
    for keyword in results['keyword_analysis']['detected_keywords']:
        print(f"- {keyword}")
    print("\nSuspicious URLs:")
    for url_result in results['url_analysis']:
        print(f"- {url_result['url']}")
        print(f"  Risk Score: {url_result['risk_score']:.2f}")
        for reason in url_result['reasons']:
            print(f"  • {reason}")
    print("\nRecommendations:")
    for rec in results['recommendations']:
        print(f"- {rec}")

if __name__ == "__main__":
    main()

