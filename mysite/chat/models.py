from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class LoggedInUser(models.Model):
    user = models.OneToOneField(
            settings.AUTH_USER_MODEL, related_name='logged_in_user', on_delete=models.CASCADE)
