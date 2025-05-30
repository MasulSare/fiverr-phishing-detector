# Fiverr Anti-Phishing Detection System

A powerful Python-based anti-phishing detection system specifically enhanced for Fiverr marketplace security. This tool helps identify and prevent phishing attempts and scam messages on the Fiverr platform.

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/happyvibess)

## Support the Project

If you find this tool helpful in protecting your Fiverr marketplace from phishing attempts, consider supporting the development:

- ☕ [Buy me a coffee](https://buymeacoffee.com/happyvibess) - Support ongoing development and maintenance
- ⭐ Star the repository - Help others find this tool
- 🐛 Report issues - Help improve the detection system
- 🚀 Share feedback - Let us know how we can make it better

Your support helps maintain and improve this security tool for the Fiverr community!

## Features

- 🔍 URL Analysis
  - Detects suspicious domains and TLDs
  - Identifies deceptive subdomains
  - Analyzes URL encoding tricks
  - Checks for IP-based URLs

- 🚫 Keyword Detection
  - Marketplace-specific scam patterns
  - Common phishing phrases
  - Fiverr-specific security terms
  - Weighted risk scoring

- ✉️ Message Header Analysis
  - Validates email headers
  - Checks sender patterns
  - Identifies domain mismatches
  - Verifies authentication headers

- 🎯 Risk Scoring System
  - Comprehensive risk assessment
  - Multiple detection layers
  - Clear recommendations
  - Customized for Fiverr

## Installation

1. Ensure Python 3.7+ is installed on your system
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   ```

3. Activate the virtual environment:
   - On Windows:
     ```bash
     .venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source .venv/bin/activate
     ```

4. Install required packages:
   ```bash
   pip install requests
   ```

## Usage

1. Basic usage with the example test case:
   ```bash
   python phishing_detector.py
   ```

2. Import in your own code:
   ```python
   from phishing_detector import PhishingDetector
   
   detector = PhishingDetector()
   results = detector.analyze_message(message_text, headers)
   ```

3. Process message files:
   ```python
   with open('message.txt', 'r') as f:
       message = f.read()
       results = detector.analyze_message(message)
   ```

## Common Fiverr Scam Patterns

The system is configured to detect common Fiverr marketplace scams:

- External payment requests
- Fake order completion messages
- Impersonation of Fiverr support
- Urgent payment/refund notices
- Account verification scams
- Fake bonus/promotion offers

## Response Actions

Based on risk levels:

- **High Risk (Score ≥ 0.7)**
  - Block message immediately
  - Report sender
  - Log incident

- **Medium Risk (Score ≥ 0.4)**
  - Flag for review
  - Monitor sender
  - Verify message contents

- **Low Risk (Score < 0.4)**
  - Normal processing
  - Standard monitoring

## Contributing

To add new patterns or improve detection:

1. Add new keywords to `suspicious_keywords`
2. Update URL patterns in `suspicious_tlds`
3. Add new sender patterns to `suspicious_sender_patterns`

## Security Note

This tool is part of your security infrastructure but should not be the only line of defense. Always combine with:

- User education
- Platform security measures
- Regular pattern updates
- Human review processes

## Support

For questions or issues:
1. Check existing documentation
2. Contact your security team lead
3. Submit detailed error reports

## Fiverr Integration Guide

### Messaging System Integration

1. Direct API Integration:
   ```python
   from fiverr_messaging import Message
   from phishing_detector import PhishingDetector

   def process_message(message: Message):
       detector = PhishingDetector()
       results = detector.analyze_message(
           message.content,
           message.headers
       )
       return handle_results(results)
   ```

2. Message Queue Integration:
   ```python
   import json
   from message_queue import MessageQueue
   from phishing_detector import PhishingDetector

   queue = MessageQueue('fiverr_messages')
   detector = PhishingDetector()

   def process_queue():
       for message in queue.receive():
           results = detector.analyze_message(
               message['content'],
               message['headers']
           )
           if results['risk_level'] == 'High':
               message.block()
           elif results['risk_level'] == 'Medium':
               message.flag_for_review()
   ```

### Common Fiverr Phishing Scenarios

1. External Payment Scam:
   ```python
   message = """
   Hi! I can offer you a better deal if you pay through PayPal directly.
   Contact me: example@payment.com
   """
   results = detector.analyze_message(message)
   # Will detect: external payment, contact outside platform
   ```

2. Fake Order Completion:
   ```python
   message = """
   URGENT: Your order #12345 is completed. Click here to receive payment:
   http://fiverr-payments.tk/claim
   """
   results = detector.analyze_message(message)
   # Will detect: suspicious URL, urgent action, payment scam
   ```

3. Support Team Impersonation:
   ```python
   message = """
   Fiverr Support Team: Your account needs verification.
   Contact: whatsapp +1234567890
   """
   results = detector.analyze_message(message)
   # Will detect: support impersonation, external contact
   ```

## Deployment Guide

### Production Deployment

1. Set up environment:
   ```bash
   python3 -m venv /opt/fiverr/phishing_detector
   source /opt/fiverr/phishing_detector/bin/activate
   pip install -r requirements.txt
   ```

2. Configure service:
   ```bash
   sudo cp phishing_detector.service /etc/systemd/system/
   sudo systemctl enable phishing_detector
   sudo systemctl start phishing_detector
   ```

3. Monitor logs:
   ```bash
   sudo journalctl -u phishing_detector -f
   ```

### High-Availability Setup

1. Load Balancer Configuration:
   - Deploy multiple instances
   - Set up health checks
   - Configure auto-scaling

2. Redis Cache Integration:
   ```python
   from redis import Redis
   redis_client = Redis(host='localhost', port=6379, db=0)
   
   def cache_detection_results(message_id, results):
       redis_client.setex(f"phishing:{message_id}", 3600, json.dumps(results))
   ```

3. Monitoring Setup:
   - Configure Prometheus metrics
   - Set up Grafana dashboards
   - Enable error alerting

### Performance Optimization

1. Batch Processing:
   ```python
   def process_batch(messages: List[Dict]):
       with ThreadPoolExecutor(max_workers=4) as executor:
           results = executor.map(detector.analyze_message, messages)
   ```

2. Caching Strategies:
   - Cache frequent patterns
   - Store known malicious URLs
   - Cache analysis results

## License

Internal use only - Fiverr Security Team
Copyright © 2025 Fiverr International Ltd. All rights reserved.
