from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework import status
from .serializers import RegisterSerializer, MotionEventSerializer
from .models import MotionEvent

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegisterSerializer

class MotionEventListView(generics.ListAPIView):
    serializer_class = MotionEventSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return MotionEvent.objects.filter(user=self.request.user).order_by('-timestamp')

class PasswordResetRequestView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://localhost:8000/api/password-reset-confirm/{uid}/{token}/"

        # Send email (for demo, just print or configure email backend)
        send_mail(
            'Password Reset Request',
            f'Click the link to reset your password: {reset_link}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        return Response({'message': 'Password reset link sent to email'}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, uidb64, token):
        password = request.data.get('password')
        password2 = request.data.get('password2')
        if not password or not password2:
            return Response({'error': 'Password and confirm password are required'}, status=status.HTTP_400_BAD_REQUEST)
        if password != password2:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        token_generator = PasswordResetTokenGenerator()
        if user is not None and token_generator.check_token(user, token):
            user.set_password(password)
            user.save()
            return Response({'message': 'Password has been reset successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid token or user'}, status=status.HTTP_400_BAD_REQUEST)
