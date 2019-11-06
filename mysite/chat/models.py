from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class ChatRoom(models.Model):
    room_name = models.CharField(max_length=50)
    message = models.TextField()

    def __str__(self):
        return str(self.room_name)


class LoggedInUser(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='logged_in_user', on_delete=models.CASCADE)
