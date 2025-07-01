from django.contrib.auth.tokens import PasswordResetTokenGenerator

class UserPasswordResetTokenGenerator(PasswordResetTokenGenerator):
    pass

password_reset_token = UserPasswordResetTokenGenerator()
