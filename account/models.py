from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from .manager import UserManager
from django.utils import timezone
from datetime import timedelta

# Create your models here.
class User(AbstractUser, PermissionsMixin):
    # Remove username field and explicitly set it as None
    username = None
    
    # Add email as the primary identifier
    email = models.EmailField('Email Address', unique=True)
    
    # Other fields
    name = models.CharField('Name', max_length=100)
    mobile = models.CharField('Mobile Number', max_length=10)
    created_at = models.DateTimeField('Created At', auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    updated_at = models.DateTimeField('Updated At', auto_now=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'mobile']
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'    
        ordering = ['-created_at']
    
    def __str__(self):
        return str(self.id) + " " + self.name

class UserOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_otp')
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=5)
    
    def __str__(self):
        return f"{self.user.email} - {self.otp}"
