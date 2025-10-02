from flask import Flask, request, jsonify
import hmac
import hashlib
import os
import subprocess
import json
import re

# --- CONFIGURATION ---
SECRET_TOKEN = os.environ.get('WEBHOOK_SECRET_TOKEN', 'DEFAULT_SECRET_TOKEN')
LOG_FILE = '/var/log/mailwizz_webhook.log'
MAIL_LOG_PATH = '/var/log/mail.log'
# --- END CONFIGURATION ---

app = Flask(__name__)

def log_message(message):
    """Appends a message to the log file."""
    with open(LOG_FILE, 'a') as f:
        f.write(f"{message}\n")

def find_sending_transport(recipient_email):
    """
    Searches the mail log for the last transport used to send to this recipient.
    This is a critical function and can be resource-intensive.
    """
    try:
        # Use 'grep' to quickly filter relevant lines.
        # We search for "to=<recipient>, ... status=sent" to find successful deliveries.
        # The 'syslog_name=postfix-ipX' tells us the transport used.
        cmd = f"grep -E 'to=<{re.escape(recipient_email)}>,.* status=sent' {MAIL_LOG_PATH} | grep -o 'syslog_name=postfix-ip[0-9]+' | tail -n 1"
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0 and result.stdout:
            # stdout will be "syslog_name=postfix-ip3"
            syslog_name = result.stdout.strip()
            transport = syslog_name.split('=')[1]
            return transport
        else:
            log_message(f"WARN: Could not find a sending transport for {recipient_email} in logs.")
            return None
    except Exception as e:
        log_message(f"ERROR: Exception while searching logs for {recipient_email}: {e}")
        return None

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """ Main endpoint to receive and process webhooks from MailWizz. """
    signature = request.headers.get('X-Mailwizz-Signature', '')
    payload = request.get_data()
    
    expected_signature = hmac.new(
        bytes(SECRET_TOKEN, 'utf-8'), msg=payload, digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        log_message(f"ERROR: Invalid signature from IP {request.remote_addr}")
        return jsonify({'status': 'error', 'message': 'Invalid signature'}), 403

    try:
        data = json.loads(payload)
        event_type = data.get('event', 'unknown').lower()
        
        # We only care about the 'open' event
        if event_type != 'open':
            return jsonify({'status': 'ignored', 'message': f'Event type "{event_type}" is not processed.'}), 200

        recipient_email = data.get('subscriber', {}).get('email')
        if not recipient_email:
            return jsonify({'status': 'ignored', 'message': 'No recipient email provided.'}), 200

        log_message(f"INFO: Received 'open' event for recipient '{recipient_email}'.")

        # --- ACTION FOR OPEN EVENT ---
        # 1. Find the IP/transport that was used to send to this recipient.
        transport = find_sending_transport(recipient_email)
        
        if transport:
            log_message(f"ACTION: Found transport '{transport}' for '{recipient_email}'. Making it sticky.")
            
            # 2. Call the new management script to create the sticky rule.
            subprocess.run([
                'sudo', 
                'recipient-ip-stick', 
                'add', 
                recipient_email, 
                transport
            ], check=True)
            
            log_message(f"SUCCESS: Created sticky rule for '{recipient_email}' to use '{transport}'.")
        else:
            log_message(f"INFO: No action taken for '{recipient_email}' as no prior delivery was found.")

        return jsonify({'status': 'success'}), 200

    except Exception as e:
        log_message(f"ERROR: Failed to process 'open' webhook. Error: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001)
