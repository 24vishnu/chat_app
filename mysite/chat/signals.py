"""
# Signals that fires when a user logs in and logs out
# We're using the inbuilt user_logged_in and user_logged_out 
# signals which fires whenever a user successfully logs in and log outs respectively.
"""
from chat.models import LoggedInUser
from django.contrib.auth import user_logged_in, user_logged_out
from django.dispatch import receiver


@receiver(user_logged_in)
def on_user_login(sender, **kwargs):
    LoggedInUser.objects.get_or_create(user=kwargs.get('user'))


@receiver(user_logged_out)
def on_user_logout(sender, **kwargs):
    LoggedInUser.objects.filter(user=kwargs.get('user')).delete()
