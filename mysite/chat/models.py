from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


# class ChatRoom(models.Model):
#     eid = models.CharField(max_length=64, unique=True)
#
#
# class ChatMessage(models.Model):
#     room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE)
#     user = models.CharField(max_length=64)
#     date = models.DateTimeField(auto_now=True, db_index=True)
#     text = models.TextField()
#
#     def to_data(self):
#         out = {'id': self.pk,
#                'from': self.user,
#                'date': self.date.auto_now(),
#                'text': self.text
#                }
#         return out


class ChatRoom(models.Model):
    room_name = models.CharField(max_length=50)
    message = models.TextField()
    # date = models.DateTimeField(auto_now=True, db_index=True)

    def __str__(self):
        return str(self.room_name)


# class RoomName(models.Model):


class LoggedInUser(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='logged_in_user', on_delete=models.CASCADE)
