import imaplib
import email
import smtplib
import re
import os
import time
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import requests

# Load environment variables from a .env file
load_dotenv()

# --- Configuration ---
# Load from environment variables with sensible defaults
IMAP_SERVER = os.getenv('GMAIL_IMAP_SERVER', 'imap.gmail.com')
IMAP_USERNAME = os.getenv('GMAIL_AUTOMATE_USER')
IMAP_PASSWORD = os.getenv('GMAIL_AUTOMATE_PASS')

SMTP_SERVER = os.getenv('GMAIL_SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('GMAIL_SMTP_PORT', 587))

# Use the consolidated Flask backend endpoint
API_URL = os.getenv('AUTOMATE_API_URL', 'http://localhost:5002/analyze_url')
CHECK_INTERVAL_SECONDS = int(os.getenv('CHECK_INTERVAL_SECONDS', 60))

def find_urls_in_text(text):
    """Finds all URLs in a given string of text."""
    # A robust regex for finding URLs
    url_regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_regex, text)

def send_email(subject, body, recipient_email):
    """Sends a reply email."""
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(IMAP_USERNAME, IMAP_PASSWORD)
            msg = MIMEMultipart()
            msg['From'] = IMAP_USERNAME
            msg['To'] = recipient_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            smtp.sendmail(IMAP_USERNAME, recipient_email, msg.as_string())
            print(f"Successfully sent reply to {recipient_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def process_emails():
    """Connects to IMAP, processes unread emails, and sends replies."""
    try:
        with imaplib.IMAP4_SSL(IMAP_SERVER) as imap:
            imap.login(IMAP_USERNAME, IMAP_PASSWORD)
            imap.select('inbox')
            print("Connected to inbox, checking for unread emails...")

            _, email_ids = imap.search(None, 'UNSEEN')
            if not email_ids[0]:
                print("No new emails.")
                return

            email_id_list = email_ids[0].split()
            print(f"Found {len(email_id_list)} new email(s).")

            for email_id in email_id_list:
                _, message_data = imap.fetch(email_id, '(RFC822)')
                raw_email = message_data[0][1]
                email_message = email.message_from_bytes(raw_email)

                sender_email = email.utils.parseaddr(email_message['From'])[1]
                email_subject = email_message['Subject']
                
                email_body = ''
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == 'text/plain':
                            email_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                else:
                    email_body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')

                urls = find_urls_in_text(email_body)
                if not urls:
                    reply_body = "No URLs were found in your email to analyze."
                    send_email(f'Re: {email_subject}', reply_body, sender_email)
                else:
                    print(f"Found URLs: {urls} in email from {sender_email}")
                    full_reply_body = "PhishNet Analysis Report:\n\n"
                    for url in urls:
                        try:
                            response = requests.post(API_URL, json={'url': url})
                            if response.status_code == 200:
                                data = response.json()
                                result_line = (
                                    f"URL: {url}\n"
                                    f"  - Result: {data.get('result', 'N/A')}\n"
                                    f"  - Score: {data.get('combined_score', 0.0):.2f}\n\n"
                                )
                                full_reply_body += result_line
                            else:
                                full_reply_body += f"URL: {url}\n  - Error: Could not analyze (API status {response.status_code})\n\n"
                        except requests.RequestException as e:
                            print(f"API request failed for {url}: {e}")
                            full_reply_body += f"URL: {url}\n  - Error: Could not connect to analysis service.\n\n"
                    
                    send_email(f'Re: {email_subject}', full_reply_body, sender_email)

                # Mark the email as read
                imap.store(email_id, '+FLAGS', r'(\Seen)')

    except Exception as e:
        print(f'An error occurred during email processing: {str(e)}')

def main():
    """Main loop to check for emails periodically."""
    if not IMAP_USERNAME or not IMAP_PASSWORD:
        print("Error: Gmail credentials (GMAIL_AUTOMATE_USER, GMAIL_AUTOMATE_PASS) are not set in the environment.")
        return

    print("Starting Gmail automation script...")
    while True:
        process_emails()
        print(f"Waiting for {CHECK_INTERVAL_SECONDS} seconds before next check...")
        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == '__main__':
    main()