from django.contrib import admin
from .models import MotionEvent

@admin.register(MotionEvent)
class MotionEventAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'timestamp', 'location')
    list_filter = ('user', 'timestamp')
    search_fields = ('location',)
