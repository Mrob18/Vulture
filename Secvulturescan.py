from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
import requests
import socket
from datetime import datetime

# Admin Contact Details
ADMIN_CONTACT = {
    "username": "@YOURANONSEC",
    "email": "Anonx@tor.onion"
}

# Function to get website information (IP, DNS, Server, OS)
def get_website_info(url):
    ip_address = socket.gethostbyname(url)
    dns = socket.getfqdn(url)
    # For demo purposes, using static info for OS and server
    server = "Apache/2.4.46 (Unix)"
    os = "Linux (Ubuntu 20.04)"
    
    return ip_address, dns, server, os

# Function to simulate vulnerability scan (for SQLi, XSS, Web Shells)
def scan_website(url):
    # Dummy data for demonstration
    vulnerabilities = [
        {
            "type": "SQL Injection",
            "location": f"{url}/login?username=guest",
            "exploit": "' OR '1'='1",
            "risk_level": "High",
            "fix": "Use parameterized queries and prepared statements"
        },
        {
            "type": "Cross-Site Scripting (XSS)",
            "location": f"{url}/contact?message=",
            "exploit": "<script>alert('XSS')</script>",
            "risk_level": "Medium",
            "fix": "Sanitize and escape user input"
        }
    ]
    
    # Return vulnerabilities found (dummy data for demonstration)
    return vulnerabilities

# Command to scan the website for vulnerabilities
def scan(update: Update, context: CallbackContext) -> None:
    url = ' '.join(context.args)
    if not url:
        update.message.reply_text("Please provide a URL to scan. Example: /scan www.yourwebsite.com")
        return

    # Get website information
    ip, dns, server, os = get_website_info(url)

    # Scan for vulnerabilities
    vulnerabilities = scan_website(url)

    # Format the result
    scan_result = f"🔎 **Website Vulnerability Scan Report** 🔍\n\n"
    scan_result += f"Website: {url}\n"
    scan_result += f"Scan initiated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    scan_result += f"🌍 **Website Information**:\n"
    scan_result += f"- **IP Address**: {ip}\n"
    scan_result += f"- **DNS**: {dns}\n"
    scan_result += f"- **Server**: {server}\n"
    scan_result += f"- **OS**: {os}\n\n"

    # Vulnerability Results
    for vuln in vulnerabilities:
        scan_result += f"1️⃣ **{vuln['type']}** - {vuln['risk_level']}\n"
        scan_result += f"- **Location**: {vuln['location']}\n"
        scan_result += f"- **Exploit**: {vuln['exploit']}\n"
        scan_result += f"- **Fix**: {vuln['fix']}\n\n"
    
    scan_result += "⚠️ **Security Note**: Always ensure you apply fixes and test your website again after making changes.\n\n"
    scan_result += f"✅ **Scan completed successfully**! Total vulnerabilities found: {len(vulnerabilities)}.\n"
    scan_result += f"Please review the issues above and take action to secure your website.\n"
    
    # Send the scan result back to the user
    update.message.reply_text(scan_result)

# Command to get admin contact info
def contact(update: Update, context: CallbackContext) -> None:
    message = (
        "📩 **Contact Admin/Owner**\n\n"
        "If you have any questions, need support, or wish to report issues, please reach out to the admin:\n\n"
        f"👤 **Admin/Author**: {ADMIN_CONTACT['@YOURANON18Y05']}\n"
        f"💬 **Telegram Username**: {ADMIN_CONTACT['@YOURANONSEC']}\n"
        f"📧 **Email**: {ADMIN_CONTACT['Anonx@tor.onion']}\n\n"
        "Feel free to message anytime for assistance."
    )
    update.message.reply_text(message)

# Main function to start the bot
def main() -> None:
    # Telegram Bot Token
    updater = Updater("8030983346:AAGMrUvRR-srADZ56cMlu4z3EqsXxuONTSU")

    # Get the dispatcher to register handlers
    dispatcher = updater.dispatcher

    # Register the command handlers
    dispatcher.add_handler(CommandHandler("scan", scan))
    dispatcher.add_handler(CommandHandler("contact", contact))

    # Start the Bot
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
