import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, request, session, send_from_directory, g
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
import bcrypt
from fpdf import FPDF
import stripe
import pymysql
from pymysql.cursors import DictCursor
from email_service import EmailService
from routes.routes import routes
from dss import init_dss_routes
import logging
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from functools import wraps

# Load environment variables early
load_dotenv()

# Initialize Flask app
app = Flask(__name__, template_folder='.')

# CSRF protection
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# Flask configuration
app.secret_key = 'my_super_secure_key_123'
app.permanent_session_lifetime = timedelta(days=1)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # Change to True in production with HTTPS

# CORS setup
allowed_origins = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, supports_credentials=True, origins=allowed_origins)

# Stripe configuration
stripe.api_key = 'sk_test_51RvFpAFnsPUQVISnTuNYVEFQlPbjSU8HBH3sxC5nFLLIBnnuJxs9cggYNENqUKD9PWdD4jPihDlkHeMTJD5l7PxF00Arox9DUH'  
if not stripe.api_key:
    raise ValueError("STRIPE_API_KEY environment variable is not set")

MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'srv607.hstgr.io'),
    'user': os.getenv('MYSQL_USER', 'u595272928_admin'),
    'password': os.getenv('MYSQL_PASSWORD', 'TWZdH=6k'),
    'database': os.getenv('MYSQL_DB', 'u595272928_dogarmedicalst'),
    'port': int(os.getenv('MYSQL_PORT', 3306)),
    'cursorclass': DictCursor
}
for key, value in MYSQL_CONFIG.items():
    if key != 'port' and value is None:
        raise ValueError(f"Missing required environment variable for {key}")

# Function to get database connection
def get_db_connection():
    return pymysql.connect(**MYSQL_CONFIG)

# Initialize email service
email_service = EmailService()

# Register blueprints
app.register_blueprint(routes)
init_dss_routes(app, get_db_connection)

# File upload configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_directory(directory):
    os.makedirs(directory, exist_ok=True)
    return directory

# Role-based access control decorator
from functools import wraps
from flask import session, jsonify

def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('role')
            if user_role not in allowed_roles:
                return jsonify({"error": "Unauthorized"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator




# Request ID for logging
@app.before_request
def before_request():
    g.request_id = os.urandom(8).hex()

def get_db_connection():
    return pymysql.connect(**MYSQL_CONFIG)

@app.route("/signsup", methods=["POST"])
@csrf.exempt
def signsup():
    try:
        data = request.get_json()
        required_fields = ["username", "email", "password", "firstName", "lastName", "role"]
        if not data or not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        if not isinstance(data["email"], str) or "@" not in data["email"]:
            return jsonify({"success": False, "message": "Invalid email format"}), 400
        if len(data["password"]) < 8:
            return jsonify({"success": False, "message": "Password must be at least 8 characters"}), 400
        if data["role"] not in ['customer', 'admin', 'employee', 'owner']:
            return jsonify({"success": False, "message": "Invalid role"}), 400

        username = data["username"]
        email = data["email"]
        password = data["password"]
        first_name = data["firstName"]
        last_name = data["lastName"]
        role = data["role"]

        verification_code = None
        code_expiry = None
        if role == 'customer':
            verification_code = email_service.generate_verification_code()
            code_expiry = datetime.now() + timedelta(minutes=10)

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    return jsonify({"success": False, "message": "Email already exists"}), 400

                cur.execute("""
                    INSERT INTO pending_users (username, first_name, last_name, email, password, role, verification_code, code_expiry)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                    verification_code = VALUES(verification_code),
                    code_expiry = VALUES(code_expiry),
                    password = VALUES(password)
                """, (username, first_name, last_name, email, hashed_pw, role, verification_code, code_expiry))
                conn.commit()

            if role == 'customer':
                if email_service.send_verification_email(email, f"{first_name} {last_name}", verification_code):
                    logger.info(f"Verification email sent to {email}", extra={'request_id': g.request_id})
                    return jsonify({
                        "success": True,
                        "message": "Verification email sent! Please check your email.",
                        "email": email
                    }), 200
                else:
                    return jsonify({"success": False, "message": "Failed to send verification email"}), 500

            return jsonify({
                "success": True,
                "message": "Registration submitted! Waiting for admin approval.",
                "email": email
            }), 200

    except Exception as e:
        logger.error(f"Signup error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route("/verify-email", methods=["POST"])
def verify_email():
    try:
        data = request.get_json()
        required_fields = ["email", "code"]
        if not data or not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Missing email or code"}), 400

        email = data["email"]
        code = data["code"]

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, first_name, last_name, email, password, role
                    FROM pending_users 
                    WHERE email = %s 
                      AND verification_code = %s 
                      AND role = 'customer'
                      AND (code_expiry IS NULL OR code_expiry > NOW())
                """, (email, code))
                pending_user = cur.fetchone()

                if not pending_user:
                    return jsonify({"success": False, "message": "Invalid or expired verification code"}), 400

                cur.execute("""
                    INSERT INTO users (username, first_name, last_name, email, password, role)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    pending_user['username'],
                    pending_user['first_name'],
                    pending_user['last_name'],
                    pending_user['email'],
                    pending_user['password'],
                    pending_user['role']
                ))

                cur.execute("DELETE FROM pending_users WHERE id = %s", (pending_user['id'],))
                conn.commit()

            return jsonify({"success": True, "message": "Email verified successfully!"}), 200

    except Exception as e:
        logger.error(f"Verification error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "Email is required"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM pending_users WHERE email = %s", (email,))
                pending_user = cur.fetchone()

                if not pending_user:
                    return jsonify({"success": False, "message": "Email not found in pending registrations"}), 404

                verification_code = email_service.generate_verification_code()
                code_expiry = datetime.now() + timedelta(minutes=10)

                cur.execute("""
                    UPDATE pending_users 
                    SET verification_code = %s, code_expiry = %s 
                    WHERE email = %s
                """, (verification_code, code_expiry, email))
                conn.commit()

            user_name = f"{pending_user['first_name']} {pending_user['last_name']}"
            if email_service.send_verification_email(email, user_name, verification_code):
                logger.info(f"Resent verification email to {email}", extra={'request_id': g.request_id})
                return jsonify({"success": True, "message": "Verification code sent again!"}), 200
            else:
                return jsonify({"success": False, "message": "Failed to send verification email"}), 500

    except Exception as e:
        logger.error(f"Resend verification error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

from flask import session

@app.route("/signsin", methods=["POST"])
@csrf.exempt
def signsin():
    data = request.get_json()
    email = data.get("email").strip()
    password = data.get("password").strip()
    
    try:
     with get_db_connection() as conn:
      with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            stored_password = user['password']
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                session.permanent = True
                session['role'] = user['role']
                session['user_id'] = user['id']

                print("✅ SESSION SET:", session)

                return jsonify({
                    "success": True,
                    "message": "Login successful!",
                    "role": user['role']
                })
            else:
                return jsonify({"success": False, "message": "Incorrect password!"})
        else:
            return jsonify({"success": False, "message": "Email not found!"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
         



@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "Email is required"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
                if not user:
                    return jsonify({"success": False, "message": "Email not registered"}), 404

                reset_code = email_service.generate_verification_code()
                code_expiry = datetime.now() + timedelta(minutes=10)

                cur.execute("""
                    INSERT INTO password_resets (email, reset_code, code_expiry)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    reset_code = VALUES(reset_code),
                    code_expiry = VALUES(code_expiry)
                """, (email, reset_code, code_expiry))
                conn.commit()

            if email_service.send_password_reset_email(email, f"{user['first_name']} {user['last_name']}", reset_code):
                logger.info(f"Password reset email sent to {email}", extra={'request_id': g.request_id})
                return jsonify({"success": True, "message": "Password reset code sent to email!"}), 200
            else:
                return jsonify({"success": False, "message": "Failed to send reset email"}), 500

    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/reset-password", methods=["POST"])
def reset_password():
    try:
        data = request.get_json()
        required_fields = ["email", "code", "newPassword"]
        if not data or not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        if len(data["newPassword"]) < 8:
            return jsonify({"success": False, "message": "New password must be at least 8 characters"}), 400

        email = data["email"]
        reset_code = data["code"]
        new_password = data["newPassword"]

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT * FROM password_resets 
                    WHERE email = %s AND reset_code = %s AND code_expiry > NOW()
                """, (email, reset_code))
                reset_entry = cur.fetchone()

                if not reset_entry:
                    return jsonify({"success": False, "message": "Invalid or expired reset code"}), 400

                hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
                cur.execute("DELETE FROM password_resets WHERE email = %s", (email,))
                conn.commit()

            logger.info(f"Password reset for {email}", extra={'request_id': g.request_id})
            return jsonify({"success": True, "message": "Password updated successfully!"}), 200

    except Exception as e:
        logger.error(f"Reset password error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.clear()
        logger.info("User logged out", extra={'request_id': g.request_id})
        return jsonify({"success": True, "message": "Logged out successfully"}), 200
    except Exception as e:
        logger.error(f"Logout error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/pending-approvals', methods=['GET'])
@require_role('owner')
def get_pending_approvals():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, first_name, last_name, email, role, code_expiry
                    FROM pending_users
                    WHERE role IN ('admin')
                    ORDER BY id DESC
                """)
                rows = cur.fetchall()

                approvals = []
                for row in rows:
                    code_expiry = row['code_expiry']
                    created_at = (code_expiry - timedelta(minutes=10)) if code_expiry else datetime.now()
                    approvals.append({
                        'id': row['id'],
                        'username': row['username'],
                        'first_name': row['first_name'],
                        'last_name': row['last_name'],
                        'email': row['email'],
                        'role': row['role'],
                        'created_at': created_at
                    })

                return jsonify(approvals), 200

    except Exception as e:
        logger.error(f"Pending approvals error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/handle-approval', methods=['POST'])
@require_role('owner')
def handle_approval():
    try:
        data = request.get_json() or {}
        approval_id = data.get('approval_id')
        action = (data.get('action') or '').strip().lower()
        return handle_approval_logic(approval_id, action, 'admin', 'owner')
    except Exception as e:
        logger.error(f"Handle approval error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/pending-approvals', methods=['GET'])
@require_role('admin')
def admin_get_pending_approvals():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, first_name, last_name, email, role, code_expiry
                    FROM pending_users
                    WHERE role = 'employee'
                    ORDER BY id DESC
                """)
                rows = cur.fetchall()

                approvals = []
                for row in rows:
                    code_expiry = row['code_expiry']
                    created_at = (code_expiry - timedelta(minutes=10)) if code_expiry else datetime.now()
                    approvals.append({
                        'id': row['id'],
                        'username': row['username'],
                        'first_name': row['first_name'],
                        'last_name': row['last_name'],
                        'email': row['email'],
                        'role': row['role'],
                        'created_at': created_at
                    })

                return jsonify(approvals), 200

    except Exception as e:
        logger.error(f"Admin pending approvals error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/handle-approval', methods=['POST'])
@require_role('admin')
@csrf.exempt
def admin_handle_approval():
    try:
        data = request.get_json() or {}
        approval_id = data.get('approval_id')
        action = (data.get('action') or '').strip().lower()
        return handle_approval_logic(approval_id, action, 'employee', 'admin')
    except Exception as e:
        logger.error(f"Admin handle approval error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

def handle_approval_logic(approval_id, action, allowed_role, approving_role):
    try:
        if not approval_id or action not in ('approve', 'reject'):
            return jsonify({"success": False, "message": "Invalid request"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM pending_users WHERE id = %s", (approval_id,))
                pending_user = cur.fetchone()
                if not pending_user:
                    return jsonify({"success": False, "message": "Pending request not found"}), 404

                if pending_user['role'] != allowed_role:
                    return jsonify({"success": False, "message": f"Only {allowed_role} approvals are handled by {approving_role}"}), 400

                if action == 'approve':
                    cur.execute("""
                        INSERT INTO users (username, first_name, last_name, email, password, role)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        pending_user['username'],
                        pending_user['first_name'],
                        pending_user['last_name'],
                        pending_user['email'],
                        pending_user['password'],
                        pending_user['role']
                    ))

                cur.execute("DELETE FROM pending_users WHERE id = %s", (approval_id,))
                conn.commit()

            logger.info(f"Approval {action} for user {pending_user['email']} by {approving_role}", extra={'request_id': g.request_id})
            return jsonify({"success": True}), 200

    except Exception as e:
        logger.error(f"Handle approval logic error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/whoami")
def whoami():
    return jsonify({
        "role": session.get("role"),
        "user_id": session.get("user_id")
    }), 200

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/api/user/<int:user_id>', methods=['GET'])
@require_role('owner', 'admin', 'employee', 'customer')
def get_user_profile(user_id):
    try:
        if session.get('user_id') != user_id and session.get('role') not in ['owner', 'admin']:
            return jsonify({"error": "Unauthorized access to profile"}), 403

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()

                if not user:
                    return jsonify({"error": "User not found"}), 404

                user_data = {
                    'id': user['id'],
                    'username': user['username'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'email': user['email'],
                    'role': user['role'],
                    'phone': user.get('phone'),
                    'date_of_birth': user.get('date_of_birth'),
                    'address': user.get('address'),
                    'city': user.get('city'),
                    'postal_code': user.get('postal_code')
                }
                return jsonify(user_data), 200

    except Exception as e:
        logger.error(f"Get user profile error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/update-profile', methods=['PUT'])
@require_role('owner', 'admin', 'employee', 'customer')
def update_profile():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"success": False, "message": "Not authenticated"}), 401

        data = request.get_json()
        required_fields = ['first_name', 'last_name']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE users SET 
                        first_name = %s, 
                        last_name = %s, 
                        phone = %s, 
                        date_of_birth = %s, 
                        address = %s, 
                        city = %s, 
                        postal_code = %s
                    WHERE id = %s
                """, (
                    data.get('first_name'),
                    data.get('last_name'),
                    data.get('phone'),
                    data.get('date_of_birth'),
                    data.get('address'),
                    data.get('city'),
                    data.get('postal_code'),
                    user_id
                ))
                conn.commit()

            logger.info(f"Profile updated for user_id {user_id}", extra={'request_id': g.request_id})
            return jsonify({"success": True, "message": "Profile updated successfully"}), 200

    except Exception as e:
        logger.error(f"Update profile error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/change-password', methods=['PUT'])
@require_role('owner', 'admin', 'employee', 'customer')
def change_password():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"success": False, "message": "Not authenticated"}), 401

        data = request.get_json()
        required_fields = ['current_password', 'new_password']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        if len(data['new_password']) < 8:
            return jsonify({"success": False, "message": "New password must be at least 8 characters"}), 400

        current_password = data['current_password']
        new_password = data['new_password']

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT password FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()

                if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
                    return jsonify({"success": False, "message": "Current password is incorrect"}), 400

                hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, user_id))
                conn.commit()

            logger.info(f"Password changed for user_id {user_id}", extra={'request_id': g.request_id})
            return jsonify({"success": True, "message": "Password changed successfully"}), 200

    except Exception as e:
        logger.error(f"Change password error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/my-orders', methods=['GET'])
@require_role('customer')
def get_my_orders():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify([]), 200

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT o.order_id, o.order_date, o.total_amount, COUNT(oi.order_item_id) as item_count
                    FROM orders o
                    LEFT JOIN order_items oi ON o.order_id = oi.order_id
                    
                    GROUP BY o.order_id
                    ORDER BY o.order_date DESC
                    LIMIT 10
               """, )
                
                # """, (user_id,))

                orders = [
                    {
                        'order_id': row['order_id'],
                        'order_date': row['order_date'],
                        'total_amount': float(row['total_amount']),
                        'item_count': row['item_count']
                    } for row in cur.fetchall()
                ]

                return jsonify(orders), 200

    except Exception as e:
        logger.error(f"Get my orders error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify([]), 500

@app.route('/api/users', methods=['GET'])
@require_role('owner', 'admin')
def get_all_users():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, first_name, last_name, email, role FROM users ORDER BY id DESC")
                users = [row for row in cur.fetchall()]
                return jsonify(users), 200

    except Exception as e:
        logger.error(f"Get all users error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/users', methods=['POST'])
@require_role('owner', 'admin')
def add_user():
    try:
        data = request.get_json()
        required_fields = ['username', 'firstName', 'lastName', 'email', 'password', 'role']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        if len(data['password']) < 8:
            return jsonify({"success": False, "message": "Password must be at least 8 characters"}), 400
        if data['role'] not in ['customer', 'admin', 'employee', 'owner']:
            return jsonify({"success": False, "message": "Invalid role"}), 400

        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE email = %s", (data['email'],))
                if cur.fetchone():
                    return jsonify({"success": False, "message": "Email already exists"}), 400

                cur.execute("""
                    INSERT INTO users (username, first_name, last_name, email, password, role)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    data['username'],
                    data['firstName'],
                    data['lastName'],
                    data['email'],
                    hashed_password,
                    data['role']
                ))
                conn.commit()

            logger.info(f"User {data['email']} added by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({"success": True, "message": "User added successfully"}), 201

    except Exception as e:
        logger.error(f"Add user error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_role('owner', 'admin')
def update_user(user_id):
    try:
        data = request.get_json()
        required_fields = ['username', 'firstName', 'lastName', 'email', 'role']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Missing required fields"}), 400
        if data['role'] not in ['customer', 'admin', 'employee', 'owner']:
            return jsonify({"success": False, "message": "Invalid role"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                if 'password' in data and data['password']:
                    if len(data['password']) < 8:
                        return jsonify({"success": False, "message": "Password must be at least 8 characters"}), 400
                    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
                    cur.execute("""
                        UPDATE users SET 
                            username = %s, 
                            first_name = %s, 
                            last_name = %s, 
                            email = %s, 
                            password = %s, 
                            role = %s
                        WHERE id = %s
                    """, (
                        data['username'],
                        data['firstName'],
                        data['lastName'],
                        data['email'],
                        hashed_password,
                        data['role'],
                        user_id
                    ))
                else:
                    cur.execute("""
                        UPDATE users SET 
                            username = %s, 
                            first_name = %s, 
                            last_name = %s, 
                            email = %s, 
                            role = %s
                        WHERE id = %s
                    """, (
                        data['username'],
                        data['firstName'],
                        data['lastName'],
                        data['email'],
                        data['role'],
                        user_id
                    ))

                if cur.rowcount == 0:
                    return jsonify({"success": False, "message": "User not found"}), 404
                conn.commit()

            logger.info(f"User {user_id} updated by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({"success": True, "message": "User updated successfully"}), 200

    except Exception as e:
        logger.error(f"Update user error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_role('owner', 'admin')
def delete_user(user_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                if cur.rowcount == 0:
                    return jsonify({"success": False, "message": "User not found"}), 404
                conn.commit()

            logger.info(f"User {user_id} deleted by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({"success": True, "message": "User deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Delete user error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/customer-ledger/<int:customer_id>', methods=['GET'])
@require_role('owner', 'admin')
def get_customer_ledger(customer_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, first_name, last_name, email FROM users WHERE id = %s", (customer_id,))
                customer_info = cur.fetchone()

                if not customer_info:
                    return jsonify({"error": "Customer not found"}), 404

                customer_data = {
                    'id': customer_info['id'],
                    'name': f"{customer_info['first_name']} {customer_info['last_name']}",
                    'email': customer_info['email']
                }

                cur.execute("""
                    SELECT 
                        o.order_date as date,
                        o.order_id as inv_no,
                        'Med-Sales' as trans_type,
                        oi.product_name as item_name,
                        CONCAT(oi.product_name, ' - Qty: ', oi.quantity) as description,
                        oi.quantity as qty,
                        oi.unit_price as rate,
                        0 as credit_amount,
                        oi.total_price as debit_amount,
                        'Dr' as dr_cr
                    FROM orders o
                    JOIN order_items oi ON o.order_id = oi.order_id
                    WHERE o.customer_id = %s
                    
                    UNION ALL
                    
                    SELECT 
                        o.order_date as date,
                        o.order_id as inv_no,
                        'Receipt Vouc' as trans_type,
                        'Cash Payment' as item_name,
                        CONCAT('Payment for Order #', o.order_id) as description,
                        1 as qty,
                        o.paid_amount as rate,
                        o.paid_amount as credit_amount,
                        0 as debit_amount,
                        'Cr' as dr_cr
                    FROM orders o
                    WHERE o.customer_id = %s AND o.paid_amount > 0
                    
                    ORDER BY date ASC, inv_no ASC
                """, (customer_id, customer_id))

                transactions = []
                running_balance = 0.0

                for row in cur.fetchall():
                    debit_amount = float(row['debit_amount']) if row['debit_amount'] else 0.0
                    credit_amount = float(row['credit_amount']) if row['credit_amount'] else 0.0
                    running_balance += debit_amount - credit_amount
                    if running_balance < 0:
                        running_balance = 0.0

                    transactions.append({
                        'date': row['date'],
                        'inv_no': row['inv_no'],
                        'trans_type': row['trans_type'],
                        'item_name': row['item_name'],
                        'description': row['description'],
                        'qty': row['qty'],
                        'rate': float(row['rate']) if row['rate'] else 0.0,
                        'credit_amount': credit_amount,
                        'debit_amount': debit_amount,
                        'balance': running_balance,
                        'dr_cr': 'Dr' if running_balance >= 0 else 'Cr'
                    })

                total_debit = sum(t['debit_amount'] for t in transactions)
                total_credit = sum(t['credit_amount'] for t in transactions)

                summary = {
                    'opening_balance': 0.0,
                    'total_debit': total_debit,
                    'total_credit': total_credit,
                    'ending_balance': abs(running_balance),
                    'ending_type': 'Dr' if running_balance >= 0 else 'Cr'
                }

                return jsonify({
                    'customer_info': customer_data,
                    'transactions': transactions,
                    'summary': summary
                }), 200

    except Exception as e:
        logger.error(f"Customer ledger error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

# @app.route('/api/products', methods=['GET'])
# @require_role('owner', 'admin', 'employee')
# def get_products():
#     try:
#         with get_db_connection() as conn:
#             with conn.cursor() as cur:
#                 cur.execute("""
#                     SELECT *
#                     FROM products
#                     WHERE stock_quantity > 0
#                     ORDER BY product_name
#                 """)
#                 products = [row for row in cur.fetchall()]
#                 return jsonify(products), 200

#     except Exception as e:
#         logger.error(f"Get products error: {str(e)}", extra={'request_id': g.request_id})
#         return jsonify({"error": str(e)}), 500

@app.route('/api/products', methods=['GET'])
@csrf.exempt
@require_role('owner', 'admin', 'employee','customer')
def get_products():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT product_id, product_name, brand, price, 
                           stock_quantity, category, expiry_date, image_path
                    FROM products
                    WHERE stock_quantity > 0
                    ORDER BY product_name
                """)
                products = [row for row in cur.fetchall()]
                return jsonify(products), 200

    except Exception as e:
        logger.error(f"Get products error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/products', methods=['POST'])
@csrf.exempt
@require_role('owner', 'admin')
def add_product():
    try:
        data = request.form
        required_fields = ['product_id', 'product_name', 'price', 'stock_quantity', 'category']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        image_path = None
        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                if image.content_length > MAX_FILE_SIZE:
                    return jsonify({"error": "File size exceeds 5MB limit"}), 400
                image_filename = secure_filename(f"product_{data['product_id']}_{image.filename}")
                image_path = os.path.join("pictures", image_filename)
                os.makedirs("pictures", exist_ok=True)
                image.save(image_path)
                image_path = f"/pictures/{image_filename}"

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT product_id FROM products WHERE product_id = %s", (data['product_id'],))
                if cur.fetchone():
                    return jsonify({"error": "Product ID already exists"}), 400

                cur.execute("""
                    INSERT INTO products (product_id, product_name, brand, description, price, 
                                        stock_quantity, category, expiry_date, image_path)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    data['product_id'],
                    data['product_name'],
                    data.get('brand', 'Generic'),
                    data.get('description', ''),
                    float(data['price']),
                    int(data['stock_quantity']),
                    data['category'],
                    data.get('expiry_date'),
                    image_path
                ))
                conn.commit()

            logger.info(f"Product {data['product_name']} added by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({"message": "Product added successfully"}), 201

    except Exception as e:
        logger.error(f"Add product error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@csrf.exempt
@require_role('owner', 'admin', 'employee')
def update_product(product_id):
    try:
        data = request.form
        image_path = None
        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                if image.content_length > MAX_FILE_SIZE:
                    return jsonify({"error": "File size exceeds 5MB limit"}), 400
                image_filename = secure_filename(f"product_{product_id}_{image.filename}")
                image_path = os.path.join("pictures", image_filename)
                os.makedirs("pictures", exist_ok=True)
                image.save(image_path)
                image_path = f"/pictures/{image_filename}"

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                update_fields = {
                    'product_name': data.get('product_name'),
                    'brand': data.get('brand', 'Generic'),
                    'description': data.get('description', ''),
                    'price': float(data['price']) if 'price' in data else None,
                    'stock_quantity': int(data['stock_quantity']) if 'stock_quantity' in data else None,
                    'category': data.get('category'),
                    'expiry_date': data.get('expiry_date'),
                    'image_path': image_path
                }
                update_fields = {k: v for k, v in update_fields.items() if v is not None}
                if not update_fields:
                    return jsonify({"error": "No fields to update"}), 400

                set_clause = ", ".join(f"{k} = %s" for k in update_fields.keys())
                query = f"UPDATE products SET {set_clause} WHERE product_id = %s"
                values = list(update_fields.values()) + [product_id]
                cur.execute(query, values)
                if cur.rowcount == 0:
                    return jsonify({"error": "Product not found"}), 404
                conn.commit()

            logger.info(f"Product {product_id} updated by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({"message": "Product updated successfully"}), 200

    except Exception as e:
        logger.error(f"Update product error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@csrf.exempt
@require_role('owner', 'admin')
def delete_product(product_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM products WHERE product_id = %s", (product_id,))
                if cur.rowcount == 0:
                    return jsonify({"error": "Product not found"}), 404
                conn.commit()

            logger.info(f"Product {product_id} deleted by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({"message": "Product deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Delete product error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/customers', methods=['GET'])
@csrf.exempt
@require_role('owner', 'admin')
def get_customers():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, first_name, last_name, email, role FROM users WHERE role = 'customer'")
                customers = [row for row in cur.fetchall()]
                return jsonify(customers), 200

    except Exception as e:
        logger.error(f"Get customers error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/customer-orders', methods=['GET'])
@require_role('owner', 'admin')
def get_customer_orders():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT order_id, customer_id, total_amount, order_date, payment_status FROM orders WHERE customer_id IS NOT NULL")
                orders = [row for row in cur.fetchall()]
                return jsonify(orders), 200

    except Exception as e:
        logger.error(f"Get customer orders error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/customer-order-details/<int:customer_id>', methods=['GET'])
@require_role('owner', 'admin', 'customer')
def get_customer_order_details(customer_id):
    try:
        if session.get('user_id') != customer_id and session.get('role') not in ['owner', 'admin']:
            return jsonify({"error": "Unauthorized access to order details"}), 403

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT o.order_id, o.total_amount, o.order_date,
                           oi.product_name, oi.quantity, oi.unit_price, o.payment_status
                    FROM orders o
                    LEFT JOIN order_items oi ON o.order_id = oi.order_id
                    WHERE o.customer_id = %s
                    ORDER BY o.order_date DESC
                """, (customer_id,))

                rows = cur.fetchall()
                orders = {}
                for row in rows:
                    order_id = row['order_id']
                    if order_id not in orders:
                        orders[order_id] = {
                            'order_id': order_id,
                            'total_amount': float(row['total_amount']),
                            'order_date': row['order_date'],
                            'payment_status': row['payment_status'],
                            'items': []
                        }

                    if row['product_name']:
                        orders[order_id]['items'].append({
                            'product_name': row['product_name'],
                            'quantity': row['quantity'],
                            'unit_price': float(row['unit_price'])
                        })

                return jsonify(list(orders.values())), 200

    except Exception as e:
        logger.error(f"Customer order details error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/save_pharmacy_order', methods=['POST'])
@csrf.exempt
@require_role('owner', 'admin')
def save_pharmacy_order():
    try:
        data = request.get_json()
        required_fields = ['supplier_name', 'expected_delivery_date', 'items']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400
        if not data['items'] or not all(isinstance(item, dict) and all(k in item for k in ['name', 'quantity', 'price']) for item in data['items']):
            return jsonify({"error": "Invalid or empty items list"}), 400

        supplier_name = data['supplier_name']
        expected_delivery_date = data['expected_delivery_date']
        items = data['items']
        total_amount = sum(item['quantity'] * item['price'] for item in items)

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO pharmacy_orders (supplier_name, expected_delivery_date, total_amount)
                    VALUES (%s, %s, %s)
                """, (supplier_name, expected_delivery_date, total_amount))
                pharmacy_order_id = cur.lastrowid

                for item in items:
                    cur.execute("""
                        INSERT INTO pharmacy_order_items (pharmacy_order_id, product_name, quantity, unit_price)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        pharmacy_order_id,
                        item['name'],
                        item['quantity'],
                        item['price']
                    ))

                conn.commit()

            pdf_path = generate_pharmacy_order_pdf(
                order_id=pharmacy_order_id,
                supplier_name=supplier_name,
                expected_delivery_date=expected_delivery_date,
                items=items,
                total_amount=total_amount
            )

            logger.info(f"Pharmacy order {pharmacy_order_id} saved by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({
                "message": "Order saved successfully",
                "pdf_url": f"/download_order_pdf/{os.path.basename(pdf_path)}"
            }), 200

    except Exception as e:
        logger.error(f"Save pharmacy order error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/download_order_pdf/<filename>')
def download_order_pdf(filename):
    try:
        filename = secure_filename(filename)
        return send_from_directory('orders', filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Download order PDF error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 404

def generate_pharmacy_order_pdf(order_id, supplier_name, expected_delivery_date, items, total_amount):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font("Arial", "B", 20)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(0, 10, "Dogar Pharmacy", ln=True, align="C")

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "B", 14)
    pdf.ln(5)
    pdf.cell(0, 10, f"Purchase Order #: PO-{order_id}", ln=True)

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Expected Delivery: {expected_delivery_date}", ln=True)
    pdf.cell(0, 10, f"Order Date: {datetime.now().strftime('%d %B %Y, %I:%M %p')}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.set_fill_color(240, 240, 255)
    pdf.cell(80, 10, "Product", 1, 0, "C", True)
    pdf.cell(30, 10, "Quantity", 1, 0, "C", True)
    pdf.cell(30, 10, "Unit Price", 1, 0, "C", True)
    pdf.cell(40, 10, "Total", 1, 1, "C", True)

    pdf.set_font("Arial", "", 12)
    for item in items:
        total = item['quantity'] * item['price']
        pdf.cell(80, 10, item['name'], 1)
        pdf.cell(30, 10, str(item['quantity']), 1, 0, "C")
        pdf.cell(30, 10, f"Rs. {item['price']:.2f}", 1, 0, "C")
        pdf.cell(40, 10, f"Rs. {total:.2f}", 1, 1, "C")

    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(140, 10, "Total Amount", 1)
    pdf.cell(40, 10, f"Rs. {total_amount:.2f}", 1, 1, "C")

    pdf_folder = ensure_directory("orders")
    filename = secure_filename(f"order_{order_id}.pdf")
    path = os.path.join(pdf_folder, filename)
    pdf.output(path)

    return path

@app.route('/api/create_payment_intent', methods=['POST'])
@csrf.exempt
def create_payment_intent():
    try:
        data = request.get_json()
        required_fields = ['amount', 'cart']
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        amount = data.get('amount')
        currency = data.get('currency', 'pkr')
        cart = data.get('cart', [])

        if not isinstance(amount, int) or amount <= 0:
            return jsonify({'error': 'Invalid amount'}), 400
        if currency not in ['pkr', 'usd']:
            return jsonify({'error': 'Unsupported currency'}), 400
        if not all(isinstance(item, dict) and all(k in item for k in ['product_id', 'name', 'quantity', 'price']) for item in cart):
            return jsonify({'error': 'Invalid cart items'}), 400

        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency=currency,
            metadata={
                'cart_items': str(len(cart)),
                'user_id': str(session.get('user_id', 'guest'))
            }
        )

        logger.info(f"Payment intent created for amount {amount} {currency}", extra={'request_id': g.request_id})
        return jsonify({
            'client_secret': intent.client_secret,
            'payment_intent_id': intent.id
        }), 200

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Create payment intent error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({'error': str(e)}), 500

@app.route('/api/expired_products', methods=['GET'])
@csrf.exempt
@require_role('owner', 'admin')
def get_expired_products():
    try:
        current_date = datetime.now().date()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT *
                    WHERE expiry_date < %s
                    ORDER BY expiry_date ASC
                """, (current_date,))
                expired_products = []
                for row in cur.fetchall():
                    expiry_date = row['expiry_date']
                    days_expired = (current_date - expiry_date).days
                    row['days_expired'] = days_expired
                    row['status'] = 'EXPIRED'
                    expired_products.append(row)
                return jsonify(expired_products), 200
    except Exception as e:
        logger.error(f"Expired products error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

@app.route('/api/save_customer_order', methods=['POST'])
@csrf.exempt
@require_role('customer')
def save_customer_order():
    try:
        data = request.get_json()
        required_fields = ['cart', 'total_amount', 'paid_amount', 'change_amount']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        cart = data.get('cart', [])
        total_amount = data.get('total_amount', 0)
        paid_amount = data.get('paid_amount', 0)
        change_amount = data.get('change_amount', 0)
        payment_method = data.get('payment_method', 'stripe')
        payment_intent_id = data.get('payment_intent_id')
        card_holder = data.get('card_holder')
        card_last_four = data.get('card_last_four')

        if not cart or not all(isinstance(item, dict) and all(k in item for k in ['product_id', 'name', 'quantity', 'price']) for item in cart):
            return jsonify({"error": "Invalid or empty cart"}), 400
        if not isinstance(total_amount, (int, float)) or total_amount < 0:
            return jsonify({"error": "Invalid total_amount"}), 400
        if not isinstance(paid_amount, (int, float)) or paid_amount < 0:
            return jsonify({"error": "Invalid paid_amount"}), 400
        if not isinstance(change_amount, (int, float)) or change_amount < 0:
            return jsonify({"error": "Invalid change_amount"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO orders (customer_id, order_date, total_amount, paid_amount, change_amount, 
                                      payment_method, payment_intent_id, card_holder, card_last_four)
                    VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s)
                """, (session.get('user_id'), total_amount, paid_amount, change_amount, 
                      payment_method, payment_intent_id, card_holder, card_last_four))
                order_id = cur.lastrowid

                for item in cart:
                    if not isinstance(item['quantity'], int) or item['quantity'] <= 0:
                        return jsonify({"error": f"Invalid quantity for {item['name']}"}), 400
                    if not isinstance(item['price'], (int, float)) or item['price'] < 0:
                        return jsonify({"error": f"Invalid price for {item['name']}"}), 400

                    cur.execute("""
                        INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        order_id,
                        item['product_id'],
                        item['name'],
                        item['quantity'],
                        item['price'],
                        item['price'] * item['quantity']
                    ))

                    cur.execute("""
                        UPDATE products 
                        SET stock_quantity = stock_quantity - %s 
                        WHERE product_id = %s AND stock_quantity >= %s
                    """, (item['quantity'], item['product_id'], item['quantity']))

                    if cur.rowcount == 0:
                        conn.rollback()
                        return jsonify({"error": f"Insufficient stock for {item['name']}"}), 400

                conn.commit()

            pdf_path = generate_customer_receipt_pdf(
                order_id=order_id,
                cart=cart,
                total_amount=total_amount,
                paid_amount=paid_amount,
                change_amount=change_amount,
                card_holder=card_holder,
                card_last_four=card_last_four,
                payment_method=payment_method
            )

            logger.info(f"Customer order {order_id} saved for user {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({
                "success": True,
                "order_id": order_id,
                "pdf_url": f"/download_customer_receipt/{os.path.basename(pdf_path)}"
            }), 200

    except Exception as e:
        logger.error(f"Save customer order error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500

def generate_customer_receipt_pdf(order_id, cart, total_amount, paid_amount, change_amount, card_holder, card_last_four, payment_method):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font("Arial", "B", 18)
    pdf.set_text_color(19, 139, 168)
    pdf.cell(0, 12, "PHARMA MASTERMIND", ln=True, align="C")

    pdf.set_font("Arial", "", 11)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 6, "Dogar Pharmacy", ln=True, align="C")
    pdf.cell(0, 6, "Bucha Chatta", ln=True, align="C")
    pdf.cell(0, 6, "License Number: 3088-6987456", ln=True, align="C")
    pdf.cell(0, 6, "Tel: 0321-1234567", ln=True, align="C")
    pdf.ln(5)

    pdf.set_draw_color(19, 139, 168)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(8)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "CUSTOMER RECEIPT", ln=True, align="C")
    pdf.ln(3)

    pdf.set_font("Arial", "", 10)
    pdf.cell(95, 6, f"Receipt No: CR-{order_id}", border=0)
    pdf.cell(95, 6, datetime.now().strftime("%d %b %Y   %H:%M"), ln=True, align="R")
    pdf.cell(95, 6, f"Customer: {card_holder or 'N/A'}", border=0)
    pdf.cell(95, 6, f"Card: ****{card_last_four or 'N/A'}", ln=True, align="R")
    pdf.ln(5)

    pdf.set_font("Arial", "B", 10)
    pdf.set_fill_color(240, 248, 255)
    pdf.cell(25, 8, "Qty", border=1, align="C", fill=True)
    pdf.cell(105, 8, "Product Description", border=1, align="C", fill=True)
    pdf.cell(30, 8, "Unit Price", border=1, align="C", fill=True)
    pdf.cell(30, 8, "Total", border=1, align="C", fill=True)
    pdf.ln()

    pdf.set_font("Arial", "", 9)
    for item in cart:
        item_total = item['price'] * item['quantity']
        pdf.cell(25, 7, str(item['quantity']), border=1, align="C")
        pdf.cell(105, 7, item['name'][:45], border=1)
        pdf.cell(30, 7, f"Rs. {item['price']:.2f}", border=1, align="R")
        pdf.cell(30, 7, f"Rs. {item_total:.2f}", border=1, align="R")
        pdf.ln()

    pdf.ln(5)
    pdf.set_font("Arial", "", 10)
    summary_y = pdf.get_y()
    pdf.rect(130, summary_y, 60, 35)
    pdf.set_xy(135, summary_y + 3)
    pdf.cell(50, 6, f"Subtotal: Rs. {total_amount:.2f}", ln=True)
    pdf.set_x(135)
    pdf.cell(50, 6, f"Tax: Rs. 0.00", ln=True)
    pdf.set_x(135)
    pdf.cell(50, 6, f"Discount: Rs. 0.00", ln=True)
    pdf.set_x(135)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(50, 6, f"Total: Rs. {total_amount:.2f}", ln=True)
    pdf.set_x(135)
    pdf.set_font("Arial", "", 9)
    pdf.cell(50, 6, f"Paid: Rs. {paid_amount:.2f}", ln=True)
    pdf.set_x(135)
    pdf.cell(50, 6, f"Change: Rs. {change_amount:.2f}", ln=True)

    pdf.ln(8)
    pdf.set_font("Arial", "", 9)
    pdf.cell(0, 6, f"Payment Method: {payment_method.capitalize()}", ln=True, align="C")
    pdf.cell(0, 6, "Payment Status: APPROVED", ln=True, align="C")

    pdf.ln(10)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 8, "Thank You for Shopping with Us!", ln=True, align="C")
    pdf.set_font("Arial", "", 8)
    pdf.cell(0, 5, "For any queries, please contact us at support@pharmamaster.com", ln=True, align="C")
    pdf.cell(0, 5, "Visit us online: www.pharmamaster.com", ln=True, align="C")

    pdf_folder = ensure_directory("customer_receipts")
    filename = secure_filename(f"customer_receipt_{order_id}.pdf")
    path = os.path.join(pdf_folder, filename)
    pdf.output(path)

    return path


@app.route('/download_customer_receipt/<filename>')
@csrf.exempt
def download_customer_receipt(filename):
    try:
        filename = secure_filename(filename)
        return send_from_directory('customer_receipts', filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Download customer receipt error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 404

@app.route('/api/save_order', methods=['POST'])
@csrf.exempt
@require_role('owner', 'admin', 'employee')
def save_order():
    try:
        data = request.get_json()
        required_fields = ['cart', 'paid_amount', 'change_amount']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        cart = data.get('cart', [])
        paid_amount = data.get('paid_amount', 0)
        change_amount = data.get('change_amount', 0)

        if not cart or not all(isinstance(item, dict) and all(k in item for k in ['product_id', 'name', 'quantity', 'price']) for item in cart):
            return jsonify({"error": "Invalid or empty cart"}), 400
        if not isinstance(paid_amount, (int, float)) or paid_amount < 0:
            return jsonify({"error": "Invalid paid_amount"}), 400
        if not isinstance(change_amount, (int, float)) or change_amount < 0:
            return jsonify({"error": "Invalid change_amount"}), 400

        total_amount = sum(item['price'] * item['quantity'] for item in cart)

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO orders (order_date, total_amount, paid_amount, change_amount)
                    VALUES (NOW(), %s, %s, %s)
                """, (total_amount, paid_amount, change_amount))
                order_id = cur.lastrowid

                for item in cart:
                    if not isinstance(item['quantity'], int) or item['quantity'] <= 0:
                        return jsonify({"error": f"Invalid quantity for {item['name']}"}), 400
                    if not isinstance(item['price'], (int, float)) or item['price'] < 0:
                        return jsonify({"error": f"Invalid price for {item['name']}"}), 400

                    cur.execute("""
                        INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        order_id,
                        item['product_id'],
                        item['name'],
                        item['quantity'],
                        item['price'],
                        item['price'] * item['quantity']
                    ))

                    cur.execute("""
                        UPDATE products 
                        SET stock_quantity = stock_quantity - %s 
                        WHERE product_id = %s AND stock_quantity >= %s
                    """, (item['quantity'], item['product_id'], item['quantity']))

                    if cur.rowcount == 0:
                        conn.rollback()
                        return jsonify({"error": f"Insufficient stock for {item['name']}"}), 400

                conn.commit()

            logger.info(f"Order {order_id} saved by {session.get('user_id')}", extra={'request_id': g.request_id})
            return jsonify({
                "success": True,
                "order_id": order_id,
                "message": "Order saved successfully"
            }), 200

    except Exception as e:
        logger.error(f"Save order error: {str(e)}", extra={'request_id': g.request_id})
        return jsonify({"error": str(e)}), 500
import os

@app.route('/api/employees', methods=['GET'])
def get_employees():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT * FROM employees')
                rows = cur.fetchall()

                employees = []
                for row in rows:
                    employee = {
                        'employee_id': row.get('employee_id'),  
                        'name': row.get('name'),
                        'email': row.get('email'),
                        'phone': row.get('phone'),
                        'cnic': row.get('cnic'),
                        'emergency': row.get('emergency'),  
                        'salary': row.get('salary')
                    }
                    employees.append(employee)

                return jsonify(employees)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/employees/<string:emp_id>', methods=['PUT'])
def update_employee(emp_id):
    try:
     data = request.json
     with get_db_connection() as conn:
      with conn.cursor() as cur:
        query = '''
            UPDATE employees
            SET name=%s, email=%s, phone=%s, cnic=%s,
                emergency=%s, role=%s, salary=%s
            WHERE employee_id=%s
        '''
        values = (
            data['name'], data['email'], data['phone'], data['cnic'],
            data['emergency_contact'], data['role'], data['salary'], emp_id
        )
        cur.execute(query, values)
        conn.commit()
        cur.close()
        return jsonify({'message': 'Employee updated successfully'})
    except Exception as e:
        print("Update error:", e)
        return jsonify({'error': str(e)}), 500




@app.route('/api/employees/<string:emp_id>', methods=['DELETE'])
def delete_employee(emp_id):
    try:
     with get_db_connection() as conn:
      with conn.cursor() as cur:
        cur.execute("DELETE FROM employees WHERE employee_id = %s", (emp_id,))
        conn.commit()
        cur.close()
        return jsonify({'message': 'Employee deleted successfully'})
    except Exception as e:
        print("Delete error:", e)
        return jsonify({'error': str(e)}), 500


@app.route('/api/invoice/<order_id>')
def get_invoice(order_id):
   with get_db_connection() as conn:
      with conn.cursor() as cursor:
    
        cursor.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
        order = cursor.fetchone()

        if not order:
            return jsonify({"error": "Order not found"}), 404

        
        cursor.execute("SELECT * FROM order_items WHERE order_id = %s", (order_id,))
        items = cursor.fetchall()

        return jsonify({
            "order": order,
            "items": items
        }), 200



@app.route('/api/process_return', methods=['POST'])
@csrf.exempt
def process_return():
    try:
     data = request.get_json()
     with get_db_connection() as conn:
      with conn.cursor() as cur:
        
        cur.execute("""
            INSERT INTO returns (invoice_number, product_name, original_quantity, 
                               return_quantity, unit_price, return_amount, return_reason, 
                               return_notes, return_date, processed_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
        """, (
            data['invoice_number'],
            data['product_name'],
            data['original_quantity'],
            data['return_quantity'],
            data['unit_price'],
            data['return_amount'],
            data['return_reason'],
            data['return_notes'],
            session.get('user_id', 'system')
        ))
        
        cur.execute("""
            UPDATE products 
            SET stock_quantity = stock_quantity + %s 
            WHERE product_name = %s
        """, (data['return_quantity'], data['product_name']))
        
        conn.commit()
        
        return jsonify({"success": True, "message": "Return processed successfully"})
        
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_ENV') != 'production')
