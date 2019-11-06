"""
event_emitter.py
EventEmitter provides multiple properties like on and emit. on property is used
to bind a function with the event and emit is used to fire an event

author : vishnu kumar
date : 1/10/2019
"""

from django.core.mail import EmailMessage
from pyee import BaseEventEmitter

ee = BaseEventEmitter()


@ee.on('messageEvent')
def send_message(mail_subject, email, message_link):
    """
    :param mail_subject: subject of the email message
    :param email: this is sender email address (HOST MAIL)
    :param message_link: message link is a message body in this parameter we
            add the a link for receiver
    :return: we return the status what is the status after sending mail (success or failed)
    """
    mail_message = EmailMessage(mail_subject, message_link, to=[email])
    status = mail_message.send()
    return status
