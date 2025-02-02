import smtplib
import json

# Email Configuration
MY_EMAIL = "sriramknff2@gmail.com"
MY_PASSWORD = "xizt iyle wrls atux"

# Load email data from data.txt
with open("data.txt", "r", encoding="utf-8") as file:
    email_data = json.load(file)

# Email content
subject = "Test Email"
message = "This is a test email sent from your Python script."

# Send email to each address in the data.txt
try:
    for recipient_name, recipient_email in email_data.items():
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()  # Start TLS encryption
            connection.login(MY_EMAIL, MY_PASSWORD)
            connection.sendmail(
                from_addr=MY_EMAIL,
                to_addrs=recipient_email,
                msg=f"Subject:{subject}\n\n{message}"
            )
        print(f"Email successfully sent to {recipient_email}")
except Exception as e:
    print(f"Failed to send email: {e}")
