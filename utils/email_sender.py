import os
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Removed getenv from here, assuming config passes values or uses current_app.config


def generate_verification_code(length=6):
    """Generate a random numeric verification code"""
    return "".join(random.choices(string.digits, k=length))


def send_email(recipient_email, subject, body):
    """
    Send an email using SMTP configured in the app.
    Requires Flask app context to access config.
    """
    # Import current_app here or pass config values as arguments
    from flask import current_app

    sender_email = current_app.config.get("EMAIL_USERNAME")
    sender_password = current_app.config.get("EMAIL_PASSWORD")
    smtp_server = current_app.config.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = current_app.config.get("SMTP_PORT", 587)  # Ensure it's an int

    if not all([sender_email, sender_password, smtp_server, smtp_port]):
        current_app.logger.error("Email configuration incomplete. Cannot send email.")
        return False

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()  # Greet server
        server.starttls()  # Secure the connection
        server.ehlo()  # Greet again after TLS
        server.login(sender_email, sender_password)
        text = message.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        current_app.logger.info(
            f"Email sent successfully to {recipient_email} (Subject: {subject})"
        )
        return True
    except smtplib.SMTPAuthenticationError as e:
        current_app.logger.error(f"SMTP Authentication Error sending email: {e}")
        return False
    except Exception as e:
        current_app.logger.error(f"Error sending email to {recipient_email}: {e}")
        return False


def send_verification_code(email, code):
    """Send a verification code email"""
    subject = "Your Verification Code for BlockInspect"
    # Consider using render_template for email bodies too
    body = f"""Hello,

Your Verification Code for BlockInspect is: {code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Regards,
BlockInspect Team
"""
    return send_email(email, subject, body)
