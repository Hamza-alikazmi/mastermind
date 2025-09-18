import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

class EmailService:
    def __init__(self):
        # Gmail SMTP configuration - you'll need to set these
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.email = "iqraraza280@gmail.com"  # Replace with your Gmail
        self.password = "gjfu klfb ftip piil"  # Replace with your Gmail App Password
        
    def generate_verification_code(self):
        """Generate a 6-digit verification code"""
        return ''.join(random.choices(string.digits, k=6))
    
    def generate_reset_token(self):
        """Generate a secure reset token"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    def send_verification_email(self, to_email, user_name, verification_code):
        """Send verification email to user"""
        try:
            msg = MIMEMultipart()
            msg['From'] = f"Pharmamastermind <{self.email}>"
            msg['To'] = to_email
            msg['Subject'] = "Verify Your PharmaMastermind Account"
            
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                    .header {{ background: linear-gradient(135deg, #138BA8, #3498DB); color: white; padding: 30px; text-align: center; }}
                    .content {{ padding: 30px; }}
                    .verification-code {{ background: #f8f9fa; border: 2px dashed #138BA8; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px; }}
                    .code {{ font-size: 32px; font-weight: bold; color: #138BA8; letter-spacing: 8px; }}
                    .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; }}
                    .btn {{ background: #138BA8; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🏥 PharmaMastermind</h1>
                        <p>Welcome to Your Health Partner</p>
                    </div>
                    <div class="content">
                        <h2>Hello {user_name}!</h2>
                        <p>Thank you for signing up with PharmaMastermind. To complete your registration, please verify your email address using the code below:</p>
                        
                        <div class="verification-code">
                            <p>Your Verification Code:</p>
                            <div class="code">{verification_code}</div>
                        </div>
                        
                        <p>This code will expire in 10 minutes for security reasons.</p>
                        <p>If you didn't create an account with us, please ignore this email.</p>
                        
                        <a href="http://127.0.0.1:5000/verification" class="btn">Verify Now</a>
                    </div>
                    <div class="footer">
                        <p>© 2024 PharmaMastermind. All rights reserved.</p>
                        <p>Dogar Pharmacy, Bucha Chatta</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email, self.password)
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"Error sending verification email: {str(e)}")
            return False
    
    def send_password_reset_email(self, to_email, user_name, reset_token):
        """Send password reset email"""
        try:
            reset_link = f"http://127.0.0.1:5000/reset-password?token={reset_token}"
            
            msg = MIMEMultipart()
            msg['From'] = self.email
            msg['To'] = to_email
            msg['Subject'] = "Reset Your PharmaMastermind Password"
            
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                    .header {{ background: linear-gradient(135deg, #E74C3C, #F39C12); color: white; padding: 30px; text-align: center; }}
                    .content {{ padding: 30px; }}
                    .reset-code {{ background: #f8f9fa; border: 2px dashed #E74C3C; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px; }}
                    .code {{ font-size: 32px; font-weight: bold; color: #E74C3C; letter-spacing: 8px; }}
                    .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; }}
                    .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Password Reset</h1>
                        <p>PharmaMastermind Security</p>
                    </div>
                    <div class="content">
                        <h2>Hello {user_name}!</h2>
                        <p>We received a request to reset your password for your PharmaMastermind account.</p>
                        
                        <p>Use the following code to reset your password:</p>
                        
                        <div class="reset-code">
                            <p>Your Reset Code:</p>
                            <div class="code">{reset_token}</div>
                        </div>
                        
                        <div class="warning">
                            <strong>⚠️ Security Notice:</strong>
                            <ul>
                                <li>This code will expire in 10 minutes</li>
                                <li>If you didn't request this reset, please ignore this email</li>
                                <li>Never share this code with anyone</li>
                            </ul>
                        </div>
                    </div>
                    <div class="footer">
                        <p>© 2024 PharmaMastermind. All rights reserved.</p>
                        <p>If you need help, contact us at support@pharmamaster.com</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email, self.password)
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"Error sending password reset email: {str(e)}")
            return False