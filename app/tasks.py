from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .models import User

@shared_task
def send_verification_email(user_id, token):
    try:
        user = User.objects.get(id=user_id)
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
        
        subject = 'Verify Your Email Address'
        html_message = render_to_string('emails/email_verification.html', {
            'user': user,
            'verification_url': verification_url,
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return f"Verification email sent to {user.email}"
    except User.DoesNotExist:
        return "User not found"
    except Exception as e:
        return f"Error sending email: {str(e)}"

@shared_task
def send_password_reset_email(user_id, token):
    try:
        user = User.objects.get(id=user_id)
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
        
        subject = 'Reset Your Password'
        html_message = render_to_string('emails/password_reset.html', {
            'user': user,
            'reset_url': reset_url,
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return f"Password reset email sent to {user.email}"
    except User.DoesNotExist:
        return "User not found"
    except Exception as e:
        return f"Error sending email: {str(e)}"