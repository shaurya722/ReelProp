from rest_framework import serializers
from .models import User,UserOTP
import re   
from datetime import timedelta
from .utils import create_and_send_otp

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True,min_length=8)
    confirm_password = serializers.CharField(write_only=True)
    class Meta:
        model=User
        fields=['email','password','confirm_password','name','mobile']
    
    def validate(self,value):
        if User.objects.filter(email=value['email']).exists():
            raise serializers.ValidationError('Email already exists')
        return value
    
    def validate_confirm_password(self,value):
        if self.initial_data['password']!=value:
            raise serializers.ValidationError('Password do not match')  
        return value    
    

    def validate_mobile(self, value):
        if not re.match(r'^\+?\d{10,15}$', value):
            raise serializers.ValidationError("Invalid mobile number format")
        if User.objects.filter(mobile=value).exists():
            raise serializers.ValidationError("Mobile number already exists")
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match"})
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(**validated_data)
        create_and_send_otp(user)
        return user

        

from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    remember_me = serializers.BooleanField(default=False)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        remember_me = data.get('remember_me')

        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError("Invalid email or password")

        refresh = RefreshToken.for_user(user)

        # Extend refresh token lifetime if "Remember Me"
        if remember_me:
            refresh.set_exp(lifetime=timedelta(days=30))  # 30-day refresh
        
        if not user.is_verified:
            raise serializers.ValidationError("User is not verified")
        
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'is_verified': user.is_verified,
            }
        }

    

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
            otp_obj = UserOTP.objects.get(user=user, otp=data['otp'])

            if otp_obj.is_expired():
                raise serializers.ValidationError("OTP has expired")

            return {'user': user}
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        except UserOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP")

    def save(self):
        user = self.validated_data['user']
        user.is_verified = True
        user.save()
        UserOTP.objects.filter(user=user).delete()
        return user

from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .tokens import password_reset_token

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email not found")
        return value

    def save(self):
        user = User.objects.get(email=self.validated_data['email'])
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = password_reset_token.make_token(user)

        # Send Reset Link (for now, print)
        reset_link = f"http://localhost:8000/api/auth/reset-password/?uid={uid}&token={token}"
        print(f"🟢 Password Reset Link: {reset_link}")

        return {
            'uid': uid,
            'token': token,
            'reset_link': reset_link,
        }


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        user = self.context['request'].user
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError("Old password is incorrect")
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New passwords do not match")
        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
