from django.contrib import admin
from django.urls import path, include
from django.conf.urls import url

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^', include('chat.urls', namespace='example')),
    # path('admin/', admin.site.urls),
    # path('chat/', include('chat.urls', namespace='chat'))
]
