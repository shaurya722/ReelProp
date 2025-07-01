import random
from .models import UserOTP

def generate_otp():
    return str(random.randint(100000, 999999))

def create_and_send_otp(user):
    otp = generate_otp()

    # Save OTP to DB
    UserOTP.objects.update_or_create(user=user, defaults={'otp': otp})

    # Bypass Twilio: Just print for now
    print(f"DEBUG [OTP]: OTP for {user.email} / {user.mobile} is {otp}")

    # 🔁 Later, replace with Twilio or SendGrid:
    # send_sms(user.mobile, otp)
    # send_email(user.email, otp)
