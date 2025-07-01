from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer, UserLoginSerializer, OTPVerificationSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, ChangePasswordSerializer
from rest_framework.permissions import IsAuthenticated
from .models import User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from .tokens import password_reset_token


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                "message": "User registered successfully",
                "user_id": user.id,
                "email": user.email,
                "is_verified": user.is_verified,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


class OTPVerifyView(APIView):
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "OTP verified successfully"}, status=200)
        return Response(serializer.errors, status=400)


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            result = serializer.save()
            return Response({
                "message": "Password reset link sent to email",
                "reset_link": result['reset_link']
            }, status=200)
        return Response(serializer.errors, status=400)


class ResetPasswordView(APIView):
    def post(self, request):
        uid = request.query_params.get("uid")
        token = request.query_params.get("token")

        if not uid or not token:
            return Response({"detail": "UID and token are required in query params"}, status=400)

        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user_id = force_str(urlsafe_base64_decode(uid))
                user = User.objects.get(pk=user_id)
            except (User.DoesNotExist, ValueError, TypeError):
                return Response({"detail": "Invalid UID"}, status=400)

            if not password_reset_token.check_token(user, token):
                return Response({"detail": "Invalid or expired token"}, status=400)

            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({"message": "Password reset successful"}, status=200)

        return Response(serializer.errors, status=400)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password changed successfully"}, status=200)
        return Response(serializer.errors, status=400)
