import smtplib
import socket
import dns.resolver
from email_validator import validate_email, EmailNotValidError

def check_credentials(email: str, password: str) -> dict:
    """
    Check if email credentials are valid by attempting SMTP login.
    """
    
    # Step 1: Validate email format
    try:
        validation = validate_email(email)
        email = validation.normalized
    except EmailNotValidError as e:
        return {
            "success": False,
            "status": "invalid_email",
            "message": f"Invalid email format: {str(e)}"
        }
    
    # Step 2: Extract domain from email
    domain = email.split("@")[1]
    
    # Step 3: Find the mail server for the domain
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mail_server = str(mx_records[0].exchange).rstrip('.')
    except Exception:
        # If no MX records, try the domain itself
        mail_server = domain
    
    # Step 4: Common SMTP ports to try
    smtp_ports = [587, 465, 25]
    
    for port in smtp_ports:
        try:
            # Try to connect and login
            if port == 587:
                server = smtplib.SMTP(mail_server, port, timeout=10)
                server.starttls()
            elif port == 465:
                server = smtplib.SMTP_SSL(mail_server, port, timeout=10)
            else:
                server = smtplib.SMTP(mail_server, port, timeout=10)
            
            # Attempt login
            server.login(email, password)
            server.quit()
            
            return {
                "success": True,
                "status": "valid",
                "message": "Credentials are valid",
                "account": {
                    "email": email,
                    "domain": domain,
                    "server": mail_server,
                    "port": port,
                }
            }
            
        except smtplib.SMTPAuthenticationError:
            return {
                "success": False,
                "status": "bad_password",
                "message": "Invalid password for this email address"
            }
        except smtplib.SMTPException as e:
            continue  # Try the next port
        except socket.timeout:
            continue
        except Exception:
            continue
    
    # If all ports failed
    return {
        "success": False,
        "status": "server_error",
        "message": "Could not connect to mail server. The server may not support SMTP login."
    }
