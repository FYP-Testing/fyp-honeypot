# cron_task.py
import schedule, time, requests, smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import pandas as pd
from report_exporter import fetch_logs
from app import app

# === Configuration ===
WEBHOOK_URL = "https://api.telegram.org/bot<token>/sendMessage"
TELEGRAM_CHAT_ID = "<your_chat_id>"
EMAIL_SENDER = "sender@example.com"
EMAIL_RECEIVER = "you@example.com"
EMAIL_PASSWORD = "your_app_password"
SMTP_SERVER = "smtp.gmail.com"

# === Scheduled Job ===
def generate_daily_report():
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)
    logs = fetch_logs_for_dates(str(yesterday), str(today))
    if not logs:
        return
    df = pd.DataFrame(logs)
    filename = f"/opt/fyp-honeypot/reports/report_{yesterday}.csv"
    df.to_csv(filename, index=False)
    send_telegram(f"Report generated for {yesterday}. Entries: {len(df)}")
    send_email(f"Report {yesterday}", f"{len(df)} logs. Saved to {filename}")

def fetch_logs_for_dates(start, end):
    with app.test_request_context():
        request.args = {"honeypot": "*", "start_date": start, "end_date": end}
        return fetch_logs()

def send_telegram(message):
    try:
        requests.post(WEBHOOK_URL, data={"chat_id": TELEGRAM_CHAT_ID, "text": message})
    except Exception as e:
        print("Telegram Error:", e)

def send_email(subject, body):
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        with smtplib.SMTP_SSL(SMTP_SERVER, 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
    except Exception as e:
        print("Email Error:", e)

schedule.every().day.at("00:05").do(generate_daily_report)

if __name__ == "__main__":
    print("Scheduler running...")
    while True:
        schedule.run_pending()
        time.sleep(60)
