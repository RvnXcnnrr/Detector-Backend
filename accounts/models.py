from django.db import models
from django.contrib.auth.models import User

class MotionEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='motion_events')
    timestamp = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"MotionEvent {self.id} by {self.user.username} at {self.timestamp}"
