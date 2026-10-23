"""Send the analyst email over SMTP. Without SMTP settings the pipeline only writes email.md."""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage


def send(subject: str, body: str, to: str, sender: str) -> None:
    host = os.environ.get("SMTP_HOST")
    if not host:
        raise RuntimeError("SMTP_HOST is not set")
    msg = EmailMessage()
    msg["Subject"], msg["To"], msg["From"] = subject, to, sender
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587"))) as smtp:
        smtp.starttls()
        if os.environ.get("SMTP_USER"):
            smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
        smtp.send_message(msg)
