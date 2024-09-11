from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, session
from pymongo import MongoClient
from emotion import analyze_sentiment_vader, analyze_sentiment_bert, recommend_coping_mechanisms
import numpy as np
import pickle
import pandas as pd
import joblib
import neattext.functions as nfx 


from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
from werkzeug.utils import secure_filename
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import random
import string
import smtplib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from dotenv import load_dotenv
import google.generativeai as genai
from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from bson.objectid import ObjectId
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler(),  # Log to console
                        logging.FileHandler('app.log')  # Log to file
                    ])
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# MongoDB Configuration
app.secret_key = os.getenv('SECRET_KEY', 'AIzaSyBfrXwYPsVklt3edTC5a3-fFIntv3MG7SA')  # Use a secure key
# MongoDB connection string
mongo_uri = "mongodb+srv://HealthAI:HealthAI123@cluster0.5y1if.mongodb.net/AI" 
 # Change 'health' to your database name
client = MongoClient(mongo_uri)

# Select the database
db = client.AI  # Use the correct database name
doctors_collection = db.doctors
appointments_collection = db.appointments
users_collection = db.users




# Configure the Generative AI model
api_key = os.getenv("GENAI_API_KEY")  # Use environment variable for security
genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-pro")
chat = model.start_chat(history=[])

def get_gemini_response(question):
    try:
        response = chat.send_message(question, stream=True)
        return response
    except genai.types.generation_types.BrokenResponseError:
        logger.error("Encountered BrokenResponseError. Retrying...")
        chat.rewind()
        response = chat.send_message(question, stream=True)
        return response
    except Exception as e:
        logger.exception("Unexpected error occurred while getting response.")
        raise e


@app.route('/bot', methods=['GET', 'POST'])
def bot():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    if 'chat_history' not in session:
        session['chat_history'] = []
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')


    if request.method == 'POST':
        user_input = request.form['input']
        if user_input:
            try:
                response = get_gemini_response(user_input)
                session['chat_history'].append(("You", user_input))
                response_texts = [chunk.text for chunk in response]
                session['chat_history'].append(("Bot", " ".join(response_texts)))
                session.modified = True  # Mark the session as modified to save changes
            except Exception as e:
                logger.exception("Error during response generation:")
                session['chat_history'].append(("Bot", "Sorry, I encountered an error. Please try again."))

            return redirect(url_for('bot'))

    return render_template('Service/bot.html',user_name=user_name,
                            user_email=user_email,
                              user_image=user_image, chat_history=session.get('chat_history', []))

#========================================================Email Code send otp Password and token===========================================================
#========================================================Email Code send otp Password token===========================================================

def generate_otp_token(length=6):
    """
    Generate a random OTP token of the given length.
    """
    characters = string.digits  # OTP consists of digits only
    otp_token = ''.join(random.choice(characters) for _ in range(length))
    return otp_token



def send_email(receiver_email, username=None, message_type=None, password=None, otp_token=None, contact_message=None, appointment_details=None):
    sender_email = "healthenginewithaiassistancee@gmail.com"
    sender_password = "oaig owrp uqxt xzxf"

    logo_path = os.path.join(app.root_path, 'static', 'img', 'logo.png')
    logo_cid = 'logo_cid'

    if message_type == 'account_creation':
        subject = "Your Account Details"
        body = f"""
        <html>
        <body>
            <img src="cid:{logo_cid}" alt="Health Engine Logo" style="width:150px;height:50px;"><br>
            <p>Dear {username},</p>
            <p>Your account has been created.</p>
            <p><b>Username:</b> {username}<br>
            <b>Password:</b> {password}</p>
            <p>Please log in and change your password after your first login to ensure your account's security.</p>
            <p>Welcome to Health Engine! We are excited to have you on board. If you have any questions, feel free to contact us.</p>
            <p>Best regards,<br>Your Health Engine Team</p>
        </body>
        </html>
        """
    elif message_type == 'otp_code':
        subject = "Your OTP Code"
        body = f"""
        <html>
        <body>
            <img src="cid:{logo_cid}" alt="Health Engine Logo" style="width:150px;height:50px;"><br>
            <p>Dear {username},</p>
            <p>Your OTP code for password reset is: <b>{otp_token}</b></p>
            <p>If you did not request a password reset, please ignore this email.</p>
            <p>Best regards,<br>Your Health Engine Team</p>
        </body>
        </html>
        """
    elif message_type == 'contact_form':
        subject = "Contact Form Message"
        body = f"""
        <html>
        <body>
            <img src="cid:{logo_cid}" alt="Health Engine Logo" style="width:150px;height:50px;"><br>
            <p>Message from contact form:</p>
            <p>{contact_message}</p>
            <p>Thank you for reaching out to us. We will get back to you shortly.</p>
            <p>Best regards,<br>Your Health Engine Team</p>
        </body>
        </html>
        """
    elif message_type == 'appointment_notification':
        subject = "Appointment Update"
        body = f"""
        <html>
        <body>
            <img src="cid:{logo_cid}" alt="Health Engine Logo" style="width:150px;height:50px;"><br>
            <p>Dear {username},</p>
            <p>{appointment_details}</p>
            <p>If you have any questions or need to reschedule, please contact us.</p>
            <p>Best regards,<br>Your Health Engine Team</p>
        </body>
        </html>
        """
    else:
        raise ValueError("Invalid message_type. Use 'account_creation', 'otp_code', 'contact_form', or 'appointment_notification'.")

    msg = MIMEMultipart('related')
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html'))

    try:
        with open(logo_path, 'rb') as logo:
            logo_image = MIMEImage(logo.read())
            logo_image.add_header('Content-ID', f'<{logo_cid}>')
            msg.attach(logo_image)
    except Exception as e:
        logging.error("Failed to attach logo image: %s", e)

    try:
        logging.debug("Attempting to send %s email...", message_type)
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        logging.info("%s email sent successfully to %s", message_type, receiver_email)
    except Exception as e:
        logging.error("Failed to send %s email to %s: %s", message_type, receiver_email, e)


#========================================================Upload File Like Image Path===========================================================
#========================================================Upload File Like Image Path===========================================================
# Ensure the upload folder exists
UPLOAD_FOLDER = 'static/profile_images'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#========================================================Home Page Routes for user doctor and admin===========================================================
#========================================================Home Page Routes for User doctor and admin===========================================================

@app.route("/")
def index():
    if 'user_id' in session:
        if session.get('is_super_admin'):
            return redirect(url_for('super_admin_dashboard'))
        elif session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return render_template("index.html")


#========================================================Login Routes===========================================================
#========================================================Login Routes===========================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if the user is already logged in
    if session.get('user_id'):
        if session.get('is_super_admin'):
            return redirect(url_for('super_admin_dashboard'))
        elif session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    # Handle POST request (login submission)
    if request.method == 'POST':
        login_input = request.form['login_input']
        password = request.form['password']

        # MongoDB query to find user by username or email
        users_collection = db.users
        user = users_collection.find_one({
            '$or': [
                {'name': login_input},
                {'email': login_input}
            ]
        })

        # Check if user exists and verify password
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])  # Convert ObjectId to string
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session['user_height'] = user.get('height', '')
            session['user_weight'] = user.get('weight', '')
            session['user_image'] = user.get('image', '')

            # Check if the user is an admin or super admin
            if user.get('is_super_admin'):
                session['is_super_admin'] = True
                flash('Super Admin login successful!', 'success')
                return redirect(url_for('super_admin_dashboard'))
            elif user.get('is_admin'):
                session['is_admin'] = True
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                session['is_admin'] = False
                session['is_super_admin'] = False
                flash('User login successful!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/email or password', 'danger')

    return render_template('Auth/login.html')
#========================================================After login Dashbord Route===========================================================
#========================================================After login Dashbord Route===========================================================
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    # Check if the user is an admin and redirect to the admin dashboard
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))

    # Get user ID from the session
    user_id = session.get('user_id')

    # Fetch the latest user information from MongoDB using the user ID
    users_collection = db.users
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    # If the user is not found in the database, log them out and redirect
    if not user:
        session.clear()  # Clear the session
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('login'))

    # Update the session with the latest user data from MongoDB
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    session['user_height'] = user.get('height', '')
    session['user_weight'] = user.get('weight', '')
    session['user_image'] = user.get('image', '')

    # Log the user's dashboard data (for debugging purposes)
    logging.debug(f"User Dashboard - User Name: {user['name']}, User Email: {user['email']}, User Height: {user.get('height', '')}, User Weight: {user.get('weight', '')}, User Image: {user.get('image', '')}")

    # Render the dashboard template and pass the user data to the template
    return render_template('index.html',
                           user_id=user_id, 
                           user_name=user['name'], 
                           user_email=user['email'], 
                           user_height=user.get('height', ''), 
                           user_weight=user.get('weight', ''), 
                           user_image=user.get('image', ''))




#========================================================Admin Dashboard/Doctor Route===========================================================
#========================================================Admin Dashboard/Doctor Route===========================================================
@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image') or 'default_image.jpg'

    users_collection = db.users
    health_info_collection = db.user_health_info
    appointments_collection = db.appointments

    try:
        patients = list(users_collection.aggregate([
            {
                '$lookup': {
                    'from': 'user_health_info',
                    'localField': '_id',
                    'foreignField': 'user_id',
                    'as': 'health_info'
                }
            },
            {'$unwind': {'path': '$health_info', 'preserveNullAndEmptyArrays': True}},
            {'$match': {'user_type': 'user', 'added_by': ObjectId(session['user_id'])}},
            {
                '$project': {
                    'id': '$_id',
                    'name': 1,
                    'email': 1,
                    'height': 1,
                    'weight': 1,
                    'image': 1,
                    'age': '$health_info.age',
                    'gender': '$health_info.gender',
                    'activity': '$health_info.activity',
                    'diet': '$health_info.diet',
                    'smoking': '$health_info.smoking',
                    'alcohol': '$health_info.alcohol',
                    'conditions': '$health_info.conditions',
                    'medications': '$health_info.medications',
                    'family_history': '$health_info.family_history',
                    'sleep': '$health_info.sleep',
                    'stress': '$health_info.stress'
                }
            }
        ]))

        one_year_ago = datetime.now() - timedelta(days=365)
        monthly_new_patients = list(users_collection.aggregate([
            {'$match': {'user_type': 'user', 'created_at': {'$gte': one_year_ago}}},
            {
                '$group': {
                    '_id': {'$dateToString': {'format': '%Y-%m', 'date': '$created_at'}},
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'_id': 1}}
        ]))

        months = [row['_id'] for row in monthly_new_patients]
        counts = [row['count'] for row in monthly_new_patients]

        total_patients = users_collection.count_documents({'user_type': 'user'})
        new_patients = users_collection.count_documents({
            'user_type': 'user',
            'created_at': {'$gte': datetime.now() - timedelta(days=30)}
        })
        total_appointments = appointments_collection.count_documents({})
        pending_appointments = appointments_collection.count_documents({'status': 'pending'})

        recent_activities = {
            'labels': months,
            'data': counts,
        }

    except Exception as e:
        flash(f'Error fetching data: {str(e)}', 'danger')
        return redirect(url_for('login'))

    return render_template('/Doctors/admin_dashboard.html',
                           user_name=user_name,
                           user_email=user_email,
                           user_image=user_image,
                           patients=patients,
                           recent_activities=recent_activities,
                           total_patients=total_patients,
                           new_patients=new_patients,
                           total_appointments=total_appointments,
                           pending_appointments=pending_appointments)


@app.route('/multiplediseasesdoctor')
def multiplediseasesdoctor():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image') or 'default_image.jpg'  # Default image if None

    return render_template('/Doctors/multiplediseasesdoctor.html',
                           user_name=user_name, user_email=user_email,
                           user_image=user_image,)

#========================================================Super Admin/main Admin Route===========================================================
#========================================================Super Admin/main Admin Route===========================================================

@app.route('/superbord')
def superbord():
    if 'is_super_admin' not in session or not session['is_super_admin']:
        flash('Unauthorized access. Only super admins can access this page.', 'danger')
        return redirect(url_for('index'))

    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image') or 'default_image.jpg'

    try:
        # Fetch all doctors from MongoDB
        doctors = list(db.users.find({'user_type': 'doctor'}))

        # Fetch all users from MongoDB
        users = list(db.users.find({'user_type': 'user'}))

        # Fetch the number of doctors and users
        num_doctors = len(doctors)
        num_users = len(users)

        # Fetch specializations and their counts
        specializations = list(db.users.aggregate([
            {'$match': {'user_type': 'doctor'}},
            {'$group': {'_id': '$specialization', 'count': {'$sum': 1}}}
        ]))

    except Exception as e:
        flash(f'Error fetching data: {str(e)}', 'danger')
        return redirect(url_for('index'))

    return render_template(
        'SuperAdmin/superbord.html',
        doctors=doctors,
        users=users,
        num_doctors=num_doctors,
        num_users=num_users,
        specializations=specializations,
        user_name=user_name,
        user_image=user_image,
        user_email=user_email
    )

@app.route('/super_admin_dashboard')
def super_admin_dashboard():
    if 'is_super_admin' not in session or not session['is_super_admin']:
        flash('Unauthorized access. Only super admins can access this page.', 'danger')
        return redirect(url_for('index'))

    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image') or 'default_image.jpg'

    try:
        # Fetch all doctors from MongoDB
        doctors = list(db.users.find({'user_type': 'doctor'}))

        # Fetch all users from MongoDB
        users = list(db.users.find({'user_type': 'user'}))

        # Fetch the number of doctors and users
        num_doctors = len(doctors)
        num_users = len(users)

        # Fetch specializations and their counts
        specializations = list(db.users.aggregate([
            {'$match': {'user_type': 'doctor'}},
            {'$group': {'_id': '$specialization', 'count': {'$sum': 1}}}
        ]))

    except Exception as e:
        flash(f'Error fetching data: {str(e)}', 'danger')
        return redirect(url_for('index'))

    return render_template(
        'SuperAdmin/super_admin_dashboard.html',
        doctors=doctors,
        users=users,
        num_doctors=num_doctors,
        num_users=num_users,
        specializations=specializations,
        user_name=user_name,
        user_image=user_image,
        user_email=user_email
    )


#========================================================SignUp Route===========================================================
#========================================================SignUP Route===========================================================

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # If the user is already logged in, redirect based on their role
    if session.get('user_id'):
        if session.get('is_super_admin'):
            return redirect(url_for('super_admin_dashboard'))
        elif session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)  # Hash the password before saving
        
        # MongoDB users collection
        users_collection = db.users

        try:
            # Create the new user data
            new_user = {
                "name": name,
                "email": email,
                "password": hashed_password,  # Store the hashed password
                "is_admin": False,             # Default role is regular user
                "is_super_admin": False,       # Default role is not super admin
                "height": "",                  # Add any default values for the user fields
                "weight": "",
                "image": ""
            }

            # Insert the new user document into MongoDB
            users_collection.insert_one(new_user)
            
            flash('Sign up successful! You can now log in.', 'success')
            return redirect(url_for('login'))

        except DuplicateKeyError:
            # If email already exists, MongoDB raises a DuplicateKeyError if email is unique
            flash('Email already exists. Please use a different email.', 'danger')

        except Exception as e:
            # Catch any other exceptions and rollback the operation
            flash(f'Error: {str(e)}', 'danger')

    return render_template('/Auth/signup.html')


#========================================================Forget Password Route===========================================================
#========================================================ForgetPassword Route===========================================================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    is_admin = session.get('is_admin', False)
    is_super_admin = session.get('is_super_admin', False)

    if request.method == 'POST':
        email = request.form.get('email')  # Use get() to avoid KeyError
        
        # Check if the email exists in the MongoDB collection
        users_collection = db.users
        user = users_collection.find_one({'email': email})
        
        if user:
            username = user.get('name')
            otp_token = generate_otp_token()
            
            # Insert OTP token into the MongoDB collection
            otp_tokens_collection = db.otp_tokens
            otp_tokens_collection.insert_one({'email': email, 'token': otp_token})
            
            # Send the OTP code to the user's email
            send_email(email, username, 'otp_code', otp_token=otp_token)
            
            flash('OTP code sent to your email.', 'success')
            return redirect(url_for('verify_otp', email=email))  # Pass email as a query parameter
        else:
            flash('Email not found.', 'danger')
    
    return render_template('Auth/forgot_password.html', is_admin=is_admin, is_super_admin=is_super_admin)

#========================================================Verify OTP Route===========================================================
#========================================================Verify OTP Route===========================================================
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    is_admin = session.get('is_admin', False)
    is_super_admin = session.get('is_super_admin', False)
    email = request.args.get('email')  # Get email from the query string

    if request.method == 'POST':
        otp_token = request.form.get('otp_token')
        new_password = request.form.get('new_password')

        if not otp_token or not new_password:
            flash('OTP token and new password are required.', 'danger')
            return redirect(url_for('verify_otp', email=email))  # Redirect to the same page to show the form

        # Verify OTP token
        otp_tokens_collection = db.otp_tokens
        token_record = otp_tokens_collection.find_one({'email': email, 'token': otp_token})

        if token_record:
            hashed_password = generate_password_hash(new_password)
            users_collection = db.users
            users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})
            
            # Remove the OTP token from the database
            otp_tokens_collection.delete_one({'email': email})
            
            flash('Password updated successfully.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP code.', 'danger')
    
    return render_template('Auth/verify_otp.html', is_admin=is_admin, is_super_admin=is_super_admin)

#========================================================Update Password Route===========================================================
#========================================================Update Password Route===========================================================
@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    is_admin = session.get('is_admin', False)
    is_super_admin = session.get('is_super_admin', False)

    if not session.get('user_id'):
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # Validate form data
        if not current_password or not new_password or not confirm_new_password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('update_password'))

        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('update_password'))

        users_collection = db.users
        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})

        if user and check_password_hash(user['password'], current_password):
            hashed_new_password = generate_password_hash(new_password)
            users_collection.update_one(
                {'_id': ObjectId(session['user_id'])},
                {'$set': {'password': hashed_new_password}}
            )
            flash('Password updated successfully!', 'success')
            return redirect(url_for('profile'))  # Redirect to the user's profile page or another appropriate page
        else:
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('update_password'))

    return render_template('Auth/update_password.html', is_admin=is_admin, is_super_admin=is_super_admin)


#========================================================Logout Route==============================================================
#========================================================Logout Route==============================================================
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


#========================================================Direct Add Doctor/Admin Route===========================================================
#========================================================Direct Add Doctor/Admin Route===========================================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    # Check if the user is logged in and is a super admin
    if 'is_super_admin' not in session or not session['is_super_admin']:
        flash('Unauthorized access. Only super admins can access this page.', 'danger')
        return redirect(url_for('index'))  # Redirect to home or another page for non-super admin users

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        is_admin = 'is_admin' in request.form
        specialization = request.form.get('specialization', '')  # Default to empty string if not present
        qualifications = request.form.get('qualifications', '')  # Default to empty string if not present
        experience = request.form.get('experience', 0)  # Default to 0 if not present
        phone = request.form.get('phone', '')  # Default to empty string if not present
        clinic_address = request.form.get('clinic_address', '')  # Default to empty string if not present

        hashed_password = generate_password_hash(password)

        users_collection = db.users
        user_data = {
            'name': username,
            'email': email,
            'password': hashed_password,
            'is_admin': is_admin,
            'user_type': user_type,
            'specialization': specialization,
            'qualifications': qualifications,
            'experience': experience,
            'phone': phone,
            'clinic_address': clinic_address
        }

        if user_type == 'doctor':
            # Insert user data into MongoDB
            users_collection.insert_one(user_data)
        else:
            # Adjust user data for non-doctor types
            user_data.pop('specialization', None)
            user_data.pop('qualifications', None)
            user_data.pop('experience', None)
            user_data.pop('phone', None)
            user_data.pop('clinic_address', None)
            users_collection.insert_one(user_data)

        flash('Registration successful!', 'success')
        return redirect(url_for('register'))  # Redirect to the register page to register more users

    return render_template('SuperAdmin/register.html', user_name=user_name, user_email=user_email, user_image=user_image)




#========================================================Profile Page for All Route===========================================================
#========================================================Profile Page for All Route===========================================================
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('user_id'):
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    
    is_super_admin = session.get('is_super_admin', False)
    
    if request.method == 'POST':
        # Handle the profile update form submission
        name = request.form.get('name')
        email = request.form.get('email')
        height = request.form.get('height')
        weight = request.form.get('weight')
        age = request.form.get('age')
        gender = request.form.get('gender')
        activity = request.form.get('activity')
        diet = request.form.get('diet')
        smoking = request.form.get('smoking')
        alcohol = request.form.get('alcohol')
        conditions = request.form.get('conditions')
        medications = request.form.get('medications')
        family_history = request.form.get('family_history')
        sleep = request.form.get('sleep')
        stress = request.form.get('stress')

        image = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image = filename

        users_collection = db.users
        health_info_collection = db.user_health_info
        
        # Update user profile
        update_query = {'_id': session['user_id']}
        update_data = {
            '$set': {
                'name': name,
                'email': email,
                'height': height,
                'weight': weight,
                'image': image
            }
        }
        users_collection.update_one(update_query, update_data)
        
        # Update health info
        health_info_data = {
            'user_id': session['user_id'],
            'height': height,
            'weight': weight,
            'age': age,
            'gender': gender,
            'activity': activity,
            'diet': diet,
            'smoking': smoking,
            'alcohol': alcohol,
            'conditions': conditions,
            'medications': medications,
            'family_history': family_history,
            'sleep': sleep,
            'stress': stress
        }
        health_info_collection.update_one(
            {'user_id': session['user_id']},
            {'$set': health_info_data},
            upsert=True
        )

        # Update the session data with the new profile information
        session['user_name'] = name
        session['user_email'] = email
        session['user_height'] = height
        session['user_weight'] = weight
        session['user_image'] = image if image else session.get('user_image', 'default.jpg')

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    else:
        # Handle the profile view
        users_collection = db.users
        health_info_collection = db.user_health_info
        
        user = users_collection.find_one({'_id': session['user_id']})
        health_info = health_info_collection.find_one({'user_id': session['user_id']})
        
        if user:
            user_data = {
                'id': user.get('_id'),
                'name': user.get('name'),
                'email': user.get('email'),
                'height': user.get('height'),
                'weight': user.get('weight'),
                'image': user.get('image', 'default.jpg'),  # Default image if user has none
                'health_info': health_info if health_info else {
                    'height': None,
                    'weight': None,
                    'age': None,
                    'gender': None,
                    'activity': None,
                    'diet': None,
                    'smoking': None,
                    'alcohol': None,
                    'conditions': None,
                    'medications': None,
                    'family_history': None,
                    'sleep': None,
                    'stress': None
                }
            }

            # Update the session data with the user's profile information
            session['user_name'] = user_data['name']
            session['user_email'] = user_data['email']
            session['user_height'] = user_data['height']
            session['user_weight'] = user_data['weight']
            session['user_image'] = user_data['image']

            return render_template('users/profile.html', user=user_data, is_super_admin=is_super_admin)
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))

        
#=-================================================Doctore profile ======================================================================
#===================================================Docotre Profile =================================================================        
@app.route('/doctorprofile', methods=['GET', 'POST'])
def doctorprofile():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image') or 'default_image.jpg'  # Default image if None

    if request.method == 'POST':
        # Handle the profile update form submission
        name = request.form.get('name')
        email = request.form.get('email')
        height = request.form.get('height')
        weight = request.form.get('weight')
        age = request.form.get('age')
        gender = request.form.get('gender')
        activity = request.form.get('activity')
        diet = request.form.get('diet')
        smoking = request.form.get('smoking')
        alcohol = request.form.get('alcohol')
        conditions = request.form.get('conditions')
        medications = request.form.get('medications')
        family_history = request.form.get('family_history')
        sleep = request.form.get('sleep')
        stress = request.form.get('stress')

        image = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image = filename

        users_collection = db.users
        health_info_collection = db.user_health_info

        # Update user profile
        update_query = {'_id': session['user_id']}
        update_data = {
            '$set': {
                'name': name,
                'email': email,
                'height': height,
                'weight': weight,
                'image': image
            }
        }
        users_collection.update_one(update_query, update_data)

        # Update health info
        health_info_data = {
            'height': height,
            'weight': weight,
            'age': age,
            'gender': gender,
            'activity': activity,
            'diet': diet,
            'smoking': smoking,
            'alcohol': alcohol,
            'conditions': conditions,
            'medications': medications,
            'family_history': family_history,
            'sleep': sleep,
            'stress': stress
        }
        health_info_collection.update_one(
            {'user_id': session['user_id']},
            {'$set': health_info_data},
            upsert=True
        )

        # Update the session data with the new profile information
        session['user_name'] = name
        session['user_email'] = email
        session['user_height'] = height
        session['user_weight'] = weight
        session['user_image'] = image if image else session['user_image']

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('doctorprofile'))

    else:
        # Handle the profile view
        users_collection = db.users
        health_info_collection = db.user_health_info

        user = users_collection.find_one({'_id': session['user_id']})
        health_info = health_info_collection.find_one({'user_id': session['user_id']})

        if user:
            user_data = {
                'id': user.get('_id'),
                'name': user.get('name'),
                'email': user.get('email'),
                'height': user.get('height'),
                'weight': user.get('weight'),
                'image': user.get('image', 'default.jpg'),  # Default image if user has none
                'health_info': health_info if health_info else {
                    'height': None,
                    'weight': None,
                    'age': None,
                    'gender': None,
                    'activity': None,
                    'diet': None,
                    'smoking': None,
                    'alcohol': None,
                    'conditions': None,
                    'medications': None,
                    'family_history': None,
                    'sleep': None,
                    'stress': None
                }
            }

            # Update the session data with the user's profile information
            session['user_name'] = user_data['name']
            session['user_email'] = user_data['email']
            session['user_height'] = user_data['height']
            session['user_weight'] = user_data['weight']
            session['user_image'] = user_data['image']

            return render_template('Doctors/doctorprofile.html', user=user_data,
                                   user_name=user_name, user_email=user_email, user_image=user_image)
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))
 


#========================================================Health Data Route===========================================================
#========================================================Health Data Route===========================================================
@app.route('/user/<int:user_id>')
def user_dashboard(user_id):
    users_collection = db.users
    health_info_collection = db.user_health_info
    
    # Fetch user health data
    health_data = health_info_collection.find_one({'user_id': user_id})
    
    # Fetch user name and image
    user_info = users_collection.find_one({'_id': user_id})

    # Define fixed example data (for demonstration purposes)
    example_data = {
        'years': ['2020', '2021', '2022', '2023'],
        'weights': [70, 72, 74, 76],  # Example weights
        'activity': [3, 4],  # Example activity levels
        'diet': [4, 5],  # Example diet levels
        'stress': [5, 6, 4, 7],  # Example stress levels
    }

    # Prepare health data
    if health_data:
        health_data = {
            'height': health_data.get('height'),
            'weight': health_data.get('weight'),
            'age': health_data.get('age'),
            'gender': health_data.get('gender'),
            'activity': health_data.get('activity'),
            'diet': health_data.get('diet'),
            'smoking': health_data.get('smoking'),
            'alcohol': health_data.get('alcohol'),
            'conditions': health_data.get('conditions'),
            'medications': health_data.get('medications'),
            'family_history': health_data.get('family_history'),
            'sleep': health_data.get('sleep'),
            'stress': health_data.get('stress')
        }
    else:
        health_data = {}

    if user_info:
        user_data = {
            'name': user_info.get('name'),
            'image': user_info.get('image', 'default.jpg')  # Default image if None
        }
    else:
        user_data = {
            'name': 'Unknown',
            'image': 'default.jpg'
        }

    # Suggest health tips based on the user's data
    health_tips = []
    if health_data.get('smoking') == 'Yes':
        health_tips.append("Consider quitting smoking to improve your overall health.")
    else:
        health_tips.append("Maintain a smoke-free lifestyle for better lung health.")

    if health_data.get('alcohol') == 'Yes':
        health_tips.append("Limit alcohol consumption to maintain liver health.")
    else:
        health_tips.append("Continue avoiding excessive alcohol consumption to protect your liver.")

    if health_data.get('sleep') and health_data['sleep'] < 7:
        health_tips.append("Ensure you get at least 7-8 hours of sleep each night.")
    else:
        health_tips.append("Maintain your healthy sleep routine to keep your energy levels up.")

    if health_data.get('activity') == 'Low':
        health_tips.append("Increase your physical activity to at least 30 minutes a day.")
    else:
        health_tips.append("Keep up your active lifestyle to stay fit and healthy.")

    return render_template('/users/health_data.html', health_data=health_data, user_data=user_data, health_tips=health_tips, example_data=example_data)



#========================================================Add Patient Admin Route===========================================================
#========================================================Add Patient Admin Route===========================================================
@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        user_type = 'user'  # Default user_type is 'user'

        if not name or not email or not phone:
            flash('Name, email, and phone are required.', 'danger')
            return redirect(url_for('add_patient'))

        username_part = email.split('@')[0]
        simple_password = f"{username_part}@123"
        hashed_password = generate_password_hash(simple_password)

        try:
            users_collection = db.users
            # Insert new patient into MongoDB
            result = users_collection.insert_one({
                'name': name,
                'email': email,
                'phone': phone,
                'password': hashed_password,
                'user_type': user_type,
                'added_by': session['user_id'],
                'is_patient': True
            })

            # Send the password to the new patient via email
            send_email(email, name, 'account_creation', password=simple_password)

            flash('Patient added successfully! An email has been sent with the password.', 'success')
            return redirect(url_for('add_patient'))
        except Exception as e:
            flash(f'An error occurred while adding the patient: {str(e)}', 'danger')
            return redirect(url_for('add_patient'))

    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    # Fetch the patients added by the current admin
    try:
        users_collection = db.users
        # Fetch patients from MongoDB
        patients = list(users_collection.find({
            'is_patient': True,
            'added_by': session['user_id']
        }, {'_id': 1, 'name': 1, 'email': 1, 'phone': 1, 'image': 1}))

    except Exception as e:
        flash(f'An error occurred while fetching patients: {str(e)}', 'danger')
        patients = []

    return render_template('Doctors/add_patient.html', user_name=user_name, user_email=user_email, 
                           user_image=user_image, patients=patients)



#========================================================View Patient Admin Route===========================================================
#========================================================View Patient Admin Route===========================================================
@app.route('/view_patient/<int:patient_id>', methods=['GET'])
def view_patient(patient_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image') or 'default_image.jpg'  # Provide a default image if None

    try:
        users_collection = db.users
        health_info_collection = db.user_health_info

        # Fetch patient basic information
        patient = users_collection.find_one({
            '_id': patient_id,
            'is_patient': True
        }, {'_id': 1, 'name': 1, 'email': 1, 'height': 1, 'weight': 1, 'image': 1})

        if not patient:
            flash('Patient not found!', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Fetch patient health information
        health_info = health_info_collection.find_one({
            'user_id': patient_id
        }, {'_id': 0, 'user_id': 0})

    except Exception as e:
        flash(f'Error fetching patient details: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

    return render_template('Doctors/view_patient.html', patient=patient, health_info=health_info,
                           user_name=user_name, 
                           user_email=user_email, 
                           user_image=user_image)




#========================================================Update Patient Admin Route===========================================================
#========================================================Update Patient Admin Route===========================================================
@app.route('/update_patient/<int:patient_id>', methods=['GET', 'POST'])
def update_patient(patient_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image') or 'default_image.jpg'  # Provide a default image if None

    users_collection = db.users

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        height = request.form.get('height')
        weight = request.form.get('weight')
        image = request.files.get('image')

        # Handle image upload
        image_filename = request.form.get('current_image')  # Preserve existing image if no new file is uploaded
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image_path = os.path.join('static/profile_images', image_filename)
            image.save(image_path)

        try:
            users_collection.update_one(
                {'_id': patient_id, 'is_patient': True},
                {'$set': {'name': name, 'email': email, 'height': height, 'weight': weight, 'image': image_filename}}
            )
            flash('Patient information updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating patient information: {str(e)}', 'danger')

        return redirect(url_for('admin_dashboard'))

    # Fetch the current information for the patient
    try:
        patient = users_collection.find_one(
            {'_id': patient_id, 'is_patient': True},
            {'_id': 1, 'name': 1, 'email': 1, 'height': 1, 'weight': 1, 'image': 1}
        )

        if not patient:
            flash('Patient not found!', 'danger')
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f'Error fetching patient details: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

    return render_template('Doctors/update_patient.html', patient=patient,
                           user_name=user_name, 
                           user_email=user_email, 
                           user_image=user_image)


#========================================================Delete Patient Admin Route===========================================================
#========================================================Delete Patient Admin Route===========================================================
@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    users_collection = db.users

    try:
        # Delete the patient document
        result = users_collection.delete_one({'_id': patient_id, 'is_patient': True})

        if result.deleted_count > 0:
            flash('Patient deleted successfully!', 'success')
        else:
            flash('Patient not found or deletion failed!', 'danger')
    except Exception as e:
        flash(f'Error deleting patient: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))


#========================================================Appointment Route===========================================================
#========================================================Appointment Route===========================================================

@app.route('/appointment', methods=['GET', 'POST'])
def appointment():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch all specializations
    specializations = doctors_collection.distinct('specialization')

    if request.method == 'POST':
        patient_name = request.form['name']
        patient_email = request.form['email']
        doctor_id = request.form['doctor']
        appointment_date = request.form['date']
        appointment_time = request.form['time']

        try:
            # Check if doctor exists
            doctor = doctors_collection.find_one({'_id': doctor_id})

            if not doctor:
                flash('Selected doctor does not exist.', 'danger')
                return redirect(url_for('appointment'))

            doctor_name = doctor['name']  # Doctor's name
            doctor_specialization = doctor['specialization']  # Doctor's specialization

            # Check if patient exists, if not create a new patient
            patient = users_collection.find_one({'email': patient_email, 'user_type': 'user'})

            if not patient:
                # Generate a random password and hash it
                password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                hashed_password = generate_password_hash(password)
                # Insert new patient into the users collection
                users_collection.insert_one({
                    'name': patient_name,
                    'email': patient_email,
                    'password': hashed_password,
                    'user_type': 'user'
                })
                patient_id = users_collection.find_one({'email': patient_email})['_id']
                # Send the password to the new user
                send_email(patient_email, patient_name, 'account_creation', password=password)
            else:
                patient_id = patient['_id']

            # Insert the appointment into the appointments collection
            appointments_collection.insert_one({
                'patient_id': patient_id,
                'patient_name': patient_name,
                'patient_email': patient_email,
                'doctor_id': doctor_id,
                'doctor_name': doctor_name,
                'doctor_specialization': doctor_specialization,
                'appointment_date': appointment_date,
                'appointment_time': appointment_time,
                'status': 'Pending'
            })

            # Send appointment confirmation email to the patient
            appointment_details = f"Your appointment with Dr. {doctor_name} ({doctor_specialization}) is scheduled for {appointment_date} at {appointment_time}."
            send_email(patient_email, patient_name, 'appointment_notification', appointment_details=appointment_details)

            flash('Appointment booked successfully!', 'success')
            return redirect(url_for('appointment'))

        except Exception as e:
            logging.error(f'Error occurred: {e}')
            flash(f'Unexpected error occurred: {e}', 'danger')

    return render_template('users/appointment.html', specializations=specializations,
                           user_name=session.get('user_name'),
                           user_email=session.get('user_email'),
                           user_height=session.get('user_height'),
                           user_weight=session.get('user_weight'),
                           user_image=session.get('user_image'))

@app.route('/get_doctors')
def get_doctors():
    specialization = request.args.get('specialization')
    if specialization:
        doctors = doctors_collection.find({'specialization': specialization})
        return jsonify([{'id': str(doc['_id']), 'name': doc['name']} for doc in doctors])
    return jsonify([])


@app.route('/manage_appointments', methods=['GET', 'POST'])
def manage_appointments():
    if not session.get('is_admin') and not session.get('is_super_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        appointment_id = request.form['appointment_id']
        action = request.form['action']
        new_date = request.form.get('new_date')
        new_time = request.form.get('new_time')

        appointment_info = appointments_collection.find_one({'_id': ObjectId(appointment_id)})
        
        if not appointment_info:
            flash('Appointment not found.', 'danger')
            return redirect(url_for('manage_appointments'))

        patient_email = appointment_info['patient_email']
        patient_name = appointment_info['patient_name']
        doctor_name = appointment_info['doctor_name']
        old_date = appointment_info['appointment_date']
        old_time = appointment_info['appointment_time']

        if action == 'approve':
            appointments_collection.update_one(
                {'_id': ObjectId(appointment_id)},
                {'$set': {'status': 'Approved'}}
            )
            appointment_details = f"Your appointment with Dr. {doctor_name} on {old_date} at {old_time} has been approved."
        elif action == 'reject':
            appointments_collection.update_one(
                {'_id': ObjectId(appointment_id)},
                {'$set': {'status': 'Rejected'}}
            )
            appointment_details = f"Your appointment with Dr. {doctor_name} on {old_date} at {old_time} has been rejected."
        elif action == 'reschedule' and new_date and new_time:
            appointments_collection.update_one(
                {'_id': ObjectId(appointment_id)},
                {'$set': {'appointment_date': new_date, 'appointment_time': new_time, 'schedule_change_request_date': None}}
            )
            appointment_details = f"Your appointment with Dr. {doctor_name} has been rescheduled to {new_date} at {new_time}."

        flash('Appointment status updated successfully!', 'success')

        # Send email notification
        send_email(patient_email, patient_name, message_type='appointment_notification', appointment_details=appointment_details)

        return redirect(url_for('manage_appointments'))

    # Fetch appointments
    appointments = list(appointments_collection.aggregate([
        {
            '$lookup': {
                'from': 'users',
                'localField': 'patient_id',
                'foreignField': '_id',
                'as': 'patient'
            }
        },
        {
            '$unwind': '$patient'
        },
        {
            '$lookup': {
                'from': 'doctors',
                'localField': 'doctor_id',
                'foreignField': '_id',
                'as': 'doctor'
            }
        },
        {
            '$unwind': '$doctor'
        },
        {
            '$project': {
                '_id': 1,
                'patient_name': '$patient.name',
                'patient_email': '$patient.email',
                'doctor_name': '$doctor.name',
                'doctor_specialization': '$doctor.specialization',
                'appointment_date': 1,
                'appointment_time': 1,
                'status': 1,
                'schedule_change_request_date': 1
            }
        }
    ]))

    return render_template('Doctors/manage_appointments.html', appointments=appointments)

#========================================================Appointment Admin Route===========================================================
#========================================================Appointemt Admin Route===========================================================

@app.route('/admin_patient_appointments/<patient_id>', methods=['GET', 'POST'])
def admin_patient_appointments(patient_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))

    # Get MongoDB collections
    appointments_collection = db.appointments
    users_collection = db.users

    appointments = []
    doctor_name = None

    try:
        # Fetch the first doctor's details for the patient
        appointment = appointments_collection.find_one({'patient_id': ObjectId(patient_id)})
        
        if appointment:
            doctor_id = appointment['doctor_id']
            doctor_details = users_collection.find_one({'_id': ObjectId(doctor_id)})

            if doctor_details:
                doctor_name = doctor_details['name']

        if request.method == 'POST':
            appointment_id = request.form['appointment_id']
            action = request.form['action']
            new_date = request.form.get('new_date')
            new_time = request.form.get('new_time')

            if action == 'approve':
                appointments_collection.update_one(
                    {'_id': ObjectId(appointment_id)},
                    {'$set': {'status': 'Approved'}}
                )
            elif action == 'reject':
                appointments_collection.update_one(
                    {'_id': ObjectId(appointment_id)},
                    {'$set': {'status': 'Rejected'}}
                )
            elif action == 'reschedule' and new_date and new_time:
                appointments_collection.update_one(
                    {'_id': ObjectId(appointment_id)},
                    {'$set': {
                        'appointment_date': new_date,
                        'appointment_time': new_time,
                        'schedule_change_request_date': None
                    }}
                )
            flash('Appointment status updated successfully!', 'success')
            return redirect(url_for('admin_patient_appointments', patient_id=patient_id))

        # Fetch all appointments for the patient
        appointments = list(appointments_collection.find({'patient_id': ObjectId(patient_id)}))

    except Exception as e:
        flash(f'Error managing appointments: {str(e)}', 'danger')
        logging.error(f'Error managing appointments: {str(e)}')

    return render_template('Doctors/admin_patient_appointments.html', patient_id=patient_id, appointments=appointments, doctor_name=doctor_name)



#========================================================Appointment Show by User Route===========================================================
#========================================================Appointmemt Show by User Route===========================================================

def format_timedelta(td):
    """Convert timedelta to a string in HH:MM AM/PM format."""
    total_seconds = int(td.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    period = 'AM' if hours < 12 else 'PM'
    hours = hours % 12
    hours = 12 if hours == 0 else hours
    return f"{hours:02}:{minutes:02} {period}"

@app.route('/user_appointments')
def user_appointments():
    if not session.get('user_id'):
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))

    user_id = ObjectId(session.get('user_id'))
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    
    # Get MongoDB collections
    appointments_collection = db.appointments
    doctors_collection = db.doctors

    try:
        # Fetch user appointments
        appointments = list(appointments_collection.find({'patient_id': user_id}))
        
        # Format appointment times if necessary
        for appointment in appointments:
            appointment['appointment_time'] = format_timedelta(appointment['appointment_time'])

        # Fetch doctor details for each appointment
        for appointment in appointments:
            doctor = doctors_collection.find_one({'_id': ObjectId(appointment['doctor_id'])})
            if doctor:
                appointment['doctor_name'] = doctor.get('name')
                appointment['specialization'] = doctor.get('specialization')

    except Exception as e:
        flash(f'Error fetching appointments: {str(e)}', 'danger')
        appointments = []

    return render_template('users/user_appointments.html', 
                           appointments=appointments, 
                           user_name=user_name, 
                           user_email=user_email, 
                           user_image=user_image)




#========================================================GET Doctor Route===========================================================
#========================================================GET doctor Route===========================================================

@app.route('/search_doctor', methods=['GET', 'POST'])
def search_doctor():
    try:
        user_name = session.get('user_name')
        user_email = session.get('user_email')
        user_image = session.get('user_image')

        # Get MongoDB collections
        doctors_collection = db.doctors

        # Initialize MongoDB query and parameters
        query = {}
        
        search_keyword = request.args.get('keyword')
        department = request.args.get('department')
        specialization = request.args.get('specialization')
        
        if search_keyword:
            search_regex = f".*{search_keyword}.*"
            query['$or'] = [
                {'name': {'$regex': search_regex, '$options': 'i'}},
                {'email': {'$regex': search_regex, '$options': 'i'}},
                {'phone': {'$regex': search_regex, '$options': 'i'}},
                {'specialization': {'$regex': search_regex, '$options': 'i'}}
            ]

        if department and department != "Department":
            query['department'] = department

        if specialization and specialization != "All Specializations":
            query['specialization'] = specialization

        # Fetch doctors based on the query
        doctors = list(doctors_collection.find(query))

        # Fetch list of specializations for filter dropdown
        specializations = doctors_collection.distinct('specialization')

        return render_template('Service/search_doctor.html', doctors=doctors, specializations=specializations, 
                               selected_specialization=specialization, user_name=user_name, 
                               user_email=user_email, user_image=user_image)
    except Exception as e:
        flash(f'Error fetching data from database: {str(e)}', 'danger')
        return render_template('Service/search_doctor.html', doctors=[], specializations=[], selected_specialization=None)





#=============================================Contact=============================================================================
#=============================================Contact=============================================================================
contact_collection = db.contact_messages

@app.route('/contact', methods=['POST'])
def contact():
    name = request.form['name']
    email = request.form['email']
    subject = request.form['subject']
    message = request.form['message']

    if not name or not email or not subject or not message:
        flash('All fields are required.', 'danger')
        return redirect(url_for('index'))

    contact_message = {
        "name": name,
        "email": email,
        "subject": subject,
        "message": message
    }

    try:
        # Insert the message into the contact_messages collection
        contact_collection.insert_one(contact_message)

        # Send the email
        send_email(email, message_type='contact_form', contact_message=contact_message)

        flash('Your message has been sent successfully!', 'success')
    except Exception as e:
        flash(f'Failed to send your message. Please try again later. Error: {str(e)}', 'danger')

    return redirect(url_for('index'))
#===============================================End Contact=======================================================
#===============================================End contact=========================================================

#===============================================Blog Start=======================================================
#===============================================Blog Start=========================================================

@app.route('/blog')
def blog():
    if 'user_id' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    # Fetch user details from MongoDB
    user = users_collection.find_one({'_id': user_id})

    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    return render_template("users/blog.html", 
                           user=user, 
                           user_name=user_name, 
                           user_email=user_email, 
                           user_image=user_image)


#========================================================Medical Packages Start===========================================================
#========================================================Medical Packages Start===========================================================
applications_collection = db.applications
packages_collection = db.packages
@app.route('/apply/<package_name>', methods=['GET', 'POST'])
def apply(package_name):
    if 'user_id' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))

    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        
        # Insert data into the MongoDB collection
        try:
            applications_collection.insert_one({
                'name': name,
                'email': email,
                'package': package_name
            })
            flash('Application submitted successfully!', 'success')
        except Exception as e:
            flash(f'Failed to submit application. Error: {str(e)}', 'danger')
        
        return redirect('/')

    # Fetch package details from MongoDB
    package = packages_collection.find_one({'name': package_name})
    
    if package:
        return render_template('/users/MedicalPackages.html', package=package,
                           user_name=user_name, 
                           user_email=user_email, 
                           user_image=user_image)
    else:
        flash('Package not found.', 'danger')
        return redirect('/')
#========================================================Medical Packages End===========================================================
#========================================================Medical Packages End===========================================================

#========================================================ML Part===========================================================
#========================================================ML Part===========================================================

# load databasedataset===================================
sym_des = pd.read_csv("Dataset/symtoms_df.csv")
precautions = pd.read_csv("Dataset/precautions_df.csv")
workout = pd.read_csv("Dataset/workout_df.csv")
description = pd.read_csv("Dataset/description.csv")
medications = pd.read_csv('Dataset/medications.csv')
diets = pd.read_csv("Dataset/diets.csv")


# load model===========================================
svc = pickle.load(open('Model/svc.pkl','rb'))
 

#============================================================
# custome and helping functions
#==========================helper funtions================

# Helper function
def helper(dis):
    desc = description[description['Disease'] == dis]['Description']
    desc = " ".join([w for w in desc])

    pre = precautions[precautions['Disease'] == dis][['Precaution_1', 'Precaution_2', 'Precaution_3', 'Precaution_4']]
    pre = [col for col in pre.values]

    med = medications[medications['Disease'] == dis]['Medication']
    med = [med for med in med.values]

    die = diets[diets['Disease'] == dis]['Diet']
    die = [die for die in die.values]

    wrkout = workout[workout['disease'] == dis]['workout']

    return desc, pre, med, die, wrkout

symptoms_dict = {'itching': 0, 'skin_rash': 1, 'nodal_skin_eruptions': 2, 'continuous_sneezing': 3, 'shivering': 4, 'chills': 5, 'joint_pain': 6, 'stomach_pain': 7, 'acidity': 8, 'ulcers_on_tongue': 9, 'muscle_wasting': 10, 'vomiting': 11, 'burning_micturition': 12, 'spotting_ urination': 13, 'fatigue': 14, 'weight_gain': 15, 'anxiety': 16, 'cold_hands_and_feets': 17, 'mood_swings': 18, 'weight_loss': 19, 'restlessness': 20, 'lethargy': 
                 21, 'patches_in_throat': 
                 22, 'irregular_sugar_level': 23, 'cough': 24, 'high_fever': 25, 'sunken_eyes': 26, 'breathlessness': 27, 'sweating': 
                 28, 'dehydration': 29, 'indigestion': 30, 'headache': 31,
                   'yellowish_skin': 32, 'dark_urine': 33, 'nausea': 34, 'loss_of_appetite': 35,
                     'pain_behind_the_eyes': 36, 'back_pain': 37, 'constipation': 38, 'abdominal_pain': 39, 
                     'diarrhoea': 40, 'mild_fever': 41, 'yellow_urine': 42, 'yellowing_of_eyes': 43, 'acute_liver_failure': 
                     44, 'fluid_overload': 45, 'swelling_of_stomach': 46, 'swelled_lymph_nodes': 47, 'malaise': 48, 
                     'blurred_and_distorted_vision': 49, 'phlegm': 50, 'throat_irritation': 51, 'redness_of_eyes': 
                     52, 'sinus_pressure': 53, 'runny_nose': 54, 'congestion': 55, 'chest_pain': 56, 'weakness_in_limbs': 57, 'fast_heart_rate':
                       58, 'pain_during_bowel_movements': 59, 'pain_in_anal_region': 60, 'bloody_stool': 61, 'irritation_in_anus': 62, 'neck_pain': 63, 'dizziness': 64, 'cramps': 65, 'bruising': 66, 'obesity': 67, 'swollen_legs': 68, 'swollen_blood_vessels': 69, 'puffy_face_and_eyes': 70, 'enlarged_thyroid': 71, 'brittle_nails': 72, 'swollen_extremeties': 73, 'excessive_hunger': 74, 'extra_marital_contacts': 75, 'drying_and_tingling_lips': 76, 'slurred_speech': 77, 'knee_pain': 78, 'hip_joint_pain': 79, 'muscle_weakness': 80, 'stiff_neck': 81, 'swelling_joints': 82, 'movement_stiffness': 83, 'spinning_movements':
                         84, 'loss_of_balance': 85, 'unsteadiness': 86, 'weakness_of_one_body_side': 87, 'loss_of_smell': 88, 'bladder_discomfort': 89, 'foul_smell_of urine': 90, 'continuous_feel_of_urine': 91, 'passage_of_gases': 92, 'internal_itching': 93, 'toxic_look_(typhos)': 94, 'depression': 95, 'irritability': 96, 'muscle_pain': 97, 'altered_sensorium': 98, 'red_spots_over_body': 99, 'belly_pain': 100, 'abnormal_menstruation': 101, 'dischromic _patches': 102, 'watering_from_eyes': 103, 'increased_appetite': 104, 'polyuria': 105, 'family_history': 106, 'mucoid_sputum': 107, 'rusty_sputum': 108, 'lack_of_concentration': 109, 'visual_disturbances': 110, 'receiving_blood_transfusion': 111, 'receiving_unsterile_injections': 112, 'coma': 113, 
                     'stomach_bleeding': 114, 'distention_of_abdomen': 115, 'history_of_alcohol_consumption': 116, 'fluid_overload.1': 117, 'blood_in_sputum': 118, 'prominent_veins_on_calf': 119, 'palpitations': 120, 'painful_walking': 121, 'pus_filled_pimples': 122, 'blackheads': 123, 'scurring': 124, 'skin_peeling': 125, 'silver_like_dusting': 126, 'small_dents_in_nails': 127, 'inflammatory_nails': 128, 'blister': 129, 'red_sore_around_nose': 130, 'yellow_crust_ooze': 131}
diseases_list = {15: 'Fungal infection', 4: 'Allergy', 16: 'GERD', 9: 'Chronic cholestasis',
                  14: 'Drug Reaction', 33: 'Peptic ulcer diseae', 1: 'AIDS', 12: 'Diabetes ', 17: 'Gastroenteritis', 6: 'Bronchial Asthma', 23: 'Hypertension ', 30: 'Migraine', 7: 'Cervical spondylosis', 32: 'Paralysis (brain hemorrhage)', 28: 'Jaundice', 29: 'Malaria', 8: 'Chicken pox', 11: 'Dengue', 37: 'Typhoid', 40: 'hepatitis A', 19: 'Hepatitis B', 20: 'Hepatitis C', 21: 'Hepatitis D', 22: 'Hepatitis E', 3: 'Alcoholic hepatitis', 36: 'Tuberculosis', 10: 'Common Cold', 34: 'Pneumonia', 13: 'Dimorphic hemmorhoids(piles)', 18: 'Heart attack', 39: 'Varicose veins', 26: 'Hypothyroidism', 24: 'Hyperthyroidism', 25: 'Hypoglycemia', 31: 'Osteoarthristis', 5: 'Arthritis', 0: '(vertigo) Paroymsal  Positional Vertigo', 2: 'Acne', 38: 'Urinary tract infection', 35: 'Psoriasis', 27: 'Impetigo'}

# Model Prediction function
def get_predicted_value(patient_symptoms):
    input_vector = np.zeros(len(symptoms_dict))
    for item in patient_symptoms:
        input_vector[symptoms_dict[item]] = 1
    return diseases_list[svc.predict([input_vector])[0]]

@app.route('/predict', methods=['GET', 'POST'])
def home():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_height = session.get('user_height')
    user_weight = session.get('user_weight')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    symptoms = list(symptoms_dict.keys())

    if request.method == 'POST':
        selected_symptoms = [
            request.form.get('symptom1'),
            request.form.get('symptom2'),
            request.form.get('symptom3'),
            request.form.get('symptom4')
        ]
        
        try:
            predicted_disease = get_predicted_value(selected_symptoms)
            dis_des, precautions, medications, rec_diet, workout = helper(predicted_disease)

            my_precautions = [precaution for precaution in precautions[0]]

            return render_template('Service/healthcheckresualt.html', predicted_disease=predicted_disease,
                                   dis_des=dis_des, my_precautions=my_precautions, medications=medications,
                                   my_diet=rec_diet, workout=workout, user_name=user_name,
                                   user_email=user_email, user_height=user_height, user_weight=user_weight,
                                   user_image=user_image)
        except KeyError as e:
            message = f"Symptom not recognized: {str(e)}. Please check your input."
            return render_template('Service/healthcheck.html', symptoms=symptoms, message=message)

    return render_template('Service/healthcheck.html', symptoms=symptoms, user_name=user_name,
                           user_email=user_email, user_height=user_height, user_weight=user_weight,
                           user_image=user_image,is_admin=is_admin)

@app.route('/healthcheck')
def healthcheck():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_height = session.get('user_height')
    user_weight = session.get('user_weight')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    return render_template('Service/healthcheck.html', user_name=user_name, user_email=user_email, 
                           user_height=user_height, user_weight=user_weight, user_image=user_image,is_admin=is_admin)
    

#================================================ madicin part =========================================================
#================================================ madicin part =========================================================

# Load your data
df = pd.read_csv('Dataset/drugsComTest_raw.csv')

# Prepare data for recommendation
df = df[['drugName', 'condition']]
df.dropna(subset=['condition'], inplace=True)
tfidf_vectorizer = TfidfVectorizer()
tfidf_matrix = tfidf_vectorizer.fit_transform(df['condition'])

# Get known conditions
known_conditions = df['condition'].unique()

# Custom filter to zip two lists
@app.template_filter('zip_lists')
def zip_lists(a, b):
    return zip(a, b)


@app.route('/medicine')
def medicine():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    # You can pass these details to the template if needed
    return render_template('/Service/Medicine.html', known_conditions=known_conditions, 
                           user_name=user_name, user_email=user_email, 
                           user_image=user_image)



@app.route('/recommend', methods=['POST'])
def recommend():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    user_condition = request.form.get('condition').strip()

    # Initialize similarity_scores
    similarity_scores = None

    # Check if the user's condition is known
    if user_condition.lower() in map(str.lower, known_conditions):
        # If known, get recommendations directly
        top_medicines = df[df['condition'].str.lower() == user_condition.lower()]['drugName'].unique()
        if top_medicines.size == 0:
            return render_template('Service/medicineresult.html', error="No relevant medicines found for the given condition.", 
                                   condition=user_condition,
                                   user_name=user_name, user_email=user_email, 
                           user_image=user_image,)
        
        # Create Google search links
        medicine_links = [
            f"https://www.google.com/search?q={medicine.replace(' ', '+')}+site:drugs.com"
            for medicine in top_medicines
        ]
    else:
        # If not known, use similarity scoring
        user_condition_tfidf = tfidf_vectorizer.transform([user_condition])
        similarity_scores = cosine_similarity(user_condition_tfidf, tfidf_matrix)

        # Check if the highest similarity score is above a threshold
        threshold = 0.1
        if similarity_scores.max() < threshold:
            return render_template('/Service/medicineresult.html', error="No relevant medicines found for the given condition.", 
                                   condition=user_condition,user_name=user_name,
                                     user_email=user_email, 
                           user_image=user_image,)

        # Get top recommendations
        top_indices = similarity_scores.argsort()[0][::-1][:10]
        top_medicines = df['drugName'].iloc[top_indices]

        # Create Google search links
        medicine_links = [
            f"https://www.google.com/search?q={medicine.replace(' ', '+')}+site:drugs.com"
            for medicine in top_medicines
        ]

    return render_template('Service/medicineresult.html', medicines=top_medicines, links=medicine_links, condition=user_condition,
                           user_name=user_name, user_email=user_email, 
                           user_image=user_image,)


#================================================ madicin part  End =========================================================
#================================================ madicin part End =========================================================


#================================================ Emotion part start =========================================================
#================================================ Emotion part start  =========================================================


@app.route('/emotions')
def emotions():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    return render_template('Service/emotions.html',
    user_name=user_name, 
                           user_email=user_email, 
                           user_image=user_image)


@app.route('/analyze', methods=['POST'])
def analyze():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')


    text = request.form['mood']
    sentiment_score_vader = analyze_sentiment_vader(text)
    sentiment_score_bert = analyze_sentiment_bert(text)
    recommendations = recommend_coping_mechanisms(sentiment_score_vader)
    return render_template('Service/emotionsresult.html', 
                           score_vader=sentiment_score_vader, 
                           score_bert=sentiment_score_bert.numpy(), 
                           recommendations=recommendations,
                           user_name=user_name, user_email=user_email, 
                           user_image=user_image)
#================================================ Emotion part text start =========================================================
#================================================ Emotion part text start =========================================================

# Load the trained pipeline
pipeline = joblib.load('Model/emotion_best.pkl')

def preprocess_text(text):
    text = nfx.remove_userhandles(text)
    text = nfx.remove_stopwords(text)
    return text


@app.route('/textemotion')
def textemotion():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    return render_template('/Service/textemotion.html', user_name=user_name, 
                           user_email=user_email, 
                           user_image=user_image)



@app.route('/predicttext', methods=['POST'])
def predicttext():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    if request.method == 'POST':
        sentence_select = request.form.get('sentence_select')
        user_input = request.form.get('user_input')
        
        if sentence_select:
            text_to_predict = sentence_select
        else:
            text_to_predict = user_input
        
        text_to_predict_clean = preprocess_text(text_to_predict)
        
        prediction = pipeline.predict([text_to_predict_clean])[0]
        prediction_proba = pipeline.predict_proba([text_to_predict_clean])
        proba_list = prediction_proba[0]
        emotions = pipeline.classes_

        emotion_prob = dict(zip(emotions, proba_list))

        return render_template('/Service/textemotionresult.html', 
                               prediction=prediction, 
                               emotion_prob=emotion_prob, 
                               user_input=text_to_predict, 
                               user_name=user_name, 
                               user_email=user_email, 
                               user_image=user_image)


#================================================ Emotion part End =========================================================
#================================================ Emotion part End  =========================================================


#================================================ multiplediseases part Start =========================================================
#================================================ multiplediseases part Start  =========================================================

@app.route('/multiplediseases')
def multiplediseases():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
        

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')

    # You can pass these details to the template if needed
    return render_template('/Service/MultipleDiseases/multiplediseases.html', known_conditions=known_conditions, 
                           user_name=user_name, user_email=user_email, 
                           user_image=user_image)



#================================================ diabetes part Start =========================================================
#================================================ diabetes part Start  =========================================================
# Load the diabetes model using joblib
model3 = joblib.load(open('Model/diabetesfile.pkl', 'rb'))

# Diabetes route
@app.route('/diabetes')
def diabetes():
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    return render_template("/Service/MultipleDiseases/diabetes.html",
                           user_name=user_name, user_email=user_email, 
                           user_image=user_image,is_admin=is_admin)

@app.route('/predictdiabetes', methods=['POST'])
def predictdiabetes():
    if request.method == 'POST':
        user_name = session.get('user_name')
        user_email = session.get('user_email')
        user_image = session.get('user_image')
        is_admin = session.get('is_admin', False)

        # Extract user input from the form
        preg = int(request.form['pregnancies'])
        glucose = int(request.form['glucose'])
        bp = int(request.form['bloodpressure'])
        st = int(request.form['skinthickness'])
        insulin = int(request.form['insulin'])
        bmi = float(request.form['bmi'])
        dpf = float(request.form['dpf'])
        age = int(request.form['age'])

        # Create a DataFrame with the correct feature names
        user_data = pd.DataFrame({
            'Pregnancies': [preg],
            'Glucose': [glucose],
            'BloodPressure': [bp],
            'SkinThickness': [st],
            'Insulin': [insulin],
            'BMI': [bmi],
            'DiabetesPedigreeFunction': [dpf],  # Corrected feature name
            'Age': [age]
        })

        # Perform diabetes prediction using your trained model
        output = model3.predict(user_data)

        # Generate a Pandas report
        prediction_report = generate_pandas_report(user_data, output)

        # Pass the prediction, report, and user data to the template
        return render_template('/Service/MultipleDiseases/diab_result.html', prediction=output, prediction_report=prediction_report, user_data=user_data,
                               user_name=user_name, user_email=user_email, 
                           user_image=user_image,is_admin=is_admin)

###############################################################################################################################################################################################

def generate_pandas_report(user_data, prediction):
    # Placeholder for report generation logic
    report_html = f"<p>User Data: {user_data.to_html()}</p><p>Prediction: {prediction}</p>"
    return report_html 

#================================================ diabetes part End =========================================================
#================================================ diabetes part End  =========================================================

#================================================ breastcancer part Start =========================================================
#================================================ breastcancer part Start  =========================================================

# Load the model using joblib and pickle 
model_cancer = pickle.load(open('Model/cAancer.pkl', 'rb')) 
 
# HTML File routes 
 
@app.route("/breastcancer") 
def breastcancer(): 
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    return render_template("/Service/MultipleDiseases/breastcancer.html", 
                           user_name=user_name, user_email=user_email, 
                           user_image=user_image,is_admin=is_admin)
 
 
# Cancer prediction route 
@app.route('/predictcancer', methods=['POST'])
def predictcancer():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    if request.method == 'POST':
        # Extract user input from the form
        clump_thickness = int(request.form['clump_thickness'])
        uniform_cell_size = int(request.form['uniform_cell_size'])
        uniform_cell_shape = int(request.form['uniform_cell_shape'])
        marginal_adhesion = int(request.form['marginal_adhesion'])
        single_epithelial_size = int(request.form['single_epithelial_size'])
        bare_nuclei = int(request.form['bare_nuclei'])
        bland_chromatin = int(request.form['bland_chromatin'])
        normal_nucleoli = int(request.form['normal_nucleoli'])
        mitoses = int(request.form['mitoses'])
    
        # Create a DataFrame with the user input
        user_data = pd.DataFrame({
            'Clump Thickness': [clump_thickness],
            'Uniform Cell size': [uniform_cell_size],
            'Uniform Cell shape': [uniform_cell_shape],
            'Marginal Adhesion': [marginal_adhesion],
            'Single Epithelial Cell Size': [single_epithelial_size],
            'Bare Nuclei': [bare_nuclei],
            'Bland Chromatin': [bland_chromatin],
            'Normal Nucleoli': [normal_nucleoli],
            'Mitoses': [mitoses],
        })
        
        # Perform cancer prediction using the trained model
        prediction = model_cancer.predict(user_data)[0]
    
        # Generate a Pandas report if risk is high
        if prediction == 4:
            prediction_report = generate_pandas_report(user_data, prediction)
            show_report = True
        else:
            prediction_report = None
            show_report = False
    
        # Pass the prediction, report, and user data to the template
        return render_template(
            '/Service/MultipleDiseases/breastcancer_result.html',
            prediction=prediction,
            prediction_report=prediction_report,
            user_data=user_data,
            user_name=user_name,
            user_email=user_email,
            user_image=user_image,
            show_report=show_report,
            is_admin=is_admin
        )


 

def generate_pandas_report(user_data, prediction): 
    # Generate a simple report based on the user data and prediction 
    report_html = f"<p>User Data: {user_data.to_html()}</p><p>Prediction: {'Malignant' if prediction == 1 else 'Benign'}</p>" 
    return report_html  
#================================================ breastcancer part End ============================================================
#================================================ breastcancer part End ============================================================

#================================================ Heart Disease part Start ===========================================================
#================================================ Heart Disease part Start  ===========================================================

# Heart Prediction Route
@app.route("/heartdisease")
def heartdisease():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    return render_template("/Service/MultipleDiseases/heartdisease.html",
                           user_name=user_name,
                           user_email=user_email,
                           user_image=user_image,
                           is_admin=is_admin)

# Prediction function
def PredictorHD(to_predict_list, size):
    to_predict = np.array(to_predict_list).reshape(1, size)
    if size == 13:
        loaded_model = joblib.load("Model/heart_model.pkl")  # Add your model filename here
        result = loaded_model.predict(to_predict)
    return result[0]

# Predict Heart Disease Route
@app.route('/predictHD', methods=["POST"])
def predictHD():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    if request.method == "POST":
        to_predict_dict = request.form.to_dict()
        to_predict_list = list(to_predict_dict.values())
        to_predict_list = list(map(float, to_predict_list))
        if len(to_predict_list) == 13:
            result = PredictorHD(to_predict_list, 13)

        if int(result) == 1:
            prediction = "Sorry! It seems you may have the disease. Please consult a doctor immediately."
            color = "text-danger"  # Red color for dangerous symptoms
        else:
            prediction = "No need to fear. You have no dangerous symptoms of the disease."
            color = "text-success"  # Green color for safe results

        # Pass the parameters to the template
        return render_template(
            "/Service/MultipleDiseases/heartdiseaseresult.html",
            user_name=user_name,
            user_email=user_email,
            user_image=user_image,
            is_admin=is_admin,
            prediction_text=prediction,
            prediction_color=color,
            age=to_predict_dict['age'],
            sex=to_predict_dict['sex'],
            cp=to_predict_dict['cp'],
            trestbps=to_predict_dict['trestbps'],
            chol=to_predict_dict['chol'],
            fbs=to_predict_dict['fbs'],
            restecg=to_predict_dict['restecg'],
            thalach=to_predict_dict['thalach'],
            exang=to_predict_dict['exang'],
            oldpeak=to_predict_dict['oldpeak'],
            slope=to_predict_dict['slope'],
            ca=to_predict_dict['ca'],
            thal=to_predict_dict['thal']
        )

#================================================ Heart Disease part End ===========================================================
#================================================ Heart Disease part End  ===========================================================

#================================================ Kidney Disease part start ===========================================================
#================================================Kidney Disease part start ===========================================================

# Load the trained model
rf_model = joblib.load('Model/Kidney.pkl')

@app.route('/kidney')
def kidney():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    return render_template('/Service/MultipleDiseases/kidney.html',
                         user_name=user_name,
                           user_email=user_email,
                           user_image=user_image,
                           is_admin=is_admin) 


@app.route('/predictkidney', methods=['POST'])
def predictkidney():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    if request.method == 'POST':
        # Retrieve form data
        features = {feature: float(request.form.get(feature)) for feature in [
            'sg', 'htn', 'hemo', 'dm', 'al', 'appet', 'rc', 'pc'
        ]}
        features_list = [features[feature] for feature in [
            'sg', 'htn', 'hemo', 'dm', 'al', 'appet', 'rc', 'pc'
        ]]

        # Convert features to numpy array
        features_array = np.array([features_list])

        # Predict using the preloaded Random Forest model
        prediction = rf_model.predict(features_array)

        # Convert prediction to human-readable label
        result = 'Sorry! It seems you may have the disease. Please consult a doctor immediately.' if prediction == 1 else 'No need to fear.You have no dangerous symptoms of the disease.'

        return render_template('/Service/MultipleDiseases/kidneyresult.html', prediction=result, **features,user_name=user_name,
                           user_email=user_email,
                           user_image=user_image,is_admin=is_admin)

#================================================ Kidney Disease part End ===========================================================
#================================================ Kidneys  Disease part End ===========================================================

#================================================Liver Disease Prediction start ===========================================================
#================================================Liver Disease Prediction  start ===========================================================

# Load the trained model
model = pickle.load(open('Model/Liver_Disease_Model.pkl', 'rb'))

@app.route('/liver',methods=['GET'])
def liver():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    return render_template('/Service/MultipleDiseases/liver.html',
                          user_name=user_name,
                           user_email=user_email,
                           user_image=user_image,is_admin=is_admin)


@app.route("/liverresult", methods=['POST'])
def liverresult():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    # Fetch user details from the session
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)
    
    if request.method == 'POST':
        try:
            Age = int(request.form['Age'])
            Gender = int(request.form['Gender'])
            Total_Bilirubin = float(request.form['Total_Bilirubin'])
            Alkaline_Phosphotase = int(request.form['Alkaline_Phosphotase'])
            Alamine_Aminotransferase = int(request.form['Alamine_Aminotransferase'])
            Aspartate_Aminotransferase = int(request.form['Aspartate_Aminotransferase'])
            Total_Protiens = float(request.form['Total_Protiens'])
            Albumin = float(request.form['Albumin'])
            Albumin_and_Globulin_Ratio = float(request.form['Albumin_and_Globulin_Ratio'])

            # Create an array with the required features (adjust this based on your model)
            values = np.array([[Age, Gender, Total_Bilirubin, Alkaline_Phosphotase]])

            # Perform the prediction
            prediction = model.predict(values)

            return render_template('/Service/MultipleDiseases/liverresult.html',
                                   user_name=user_name,
                                   user_email=user_email,
                                   user_image=user_image,
                                   is_admin=is_admin, 
                                   prediction=prediction, 
                                   Age=Age, 
                                   Gender=Gender, 
                                   Total_Bilirubin=Total_Bilirubin,
                                   Alkaline_Phosphotase=Alkaline_Phosphotase,
                                   Alamine_Aminotransferase=Alamine_Aminotransferase,
                                   Aspartate_Aminotransferase=Aspartate_Aminotransferase,
                                   Total_Protiens=Total_Protiens,
                                   Albumin=Albumin,
                                   Albumin_and_Globulin_Ratio=Albumin_and_Globulin_Ratio)  

        except ValueError as e:
            # Flash the error message
            flash(f"Error: {str(e)}", 'danger')
            return redirect(url_for('form_page'))  # Replace with your form page route
    
#================================================Liver Disease Prediction End ===========================================================
#================================================Liver Disease Prediction  End ===========================================================

#================================================Ayurvedic Medicines Prediction Start ===========================================================
#================================================Ayurvedic Medicines Prediction Start ===========================================================
@app.route('/ayurved')
def ayurved():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))

    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    # Fetch ayurvedic medicines from MongoDB
    medicines_collection = db.ayurvedic_medicines
    medicines = list(medicines_collection.find())

    return render_template('/Service/ayurved.html', medicines=medicines, user_name=user_name,
                           user_email=user_email,
                           user_image=user_image,
                           is_admin=is_admin)




@app.route('/ayurvedicmedicines')
def ayurvedicmedicines():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    # Load the dataset to get the unique diseases
    data = pd.read_csv('Dataset/ayurdataset.csv')
    diseases = data['disease'].unique().tolist()
    return render_template('/Service/ayurvedicmedicines.html', diseases=diseases,
                               user_name=user_name,
                               user_email=user_email,
                               user_image=user_image,
                               is_admin=is_admin)
    
import requests
from bs4 import BeautifulSoup
# Load the saved model and label encoders
model = joblib.load('Model/predictor.pkl')
label_encoders = joblib.load('Model/encoders.pkl')


@app.route('/ayurpredict', methods=['POST'])
def ayurpredict():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    try:
        # Extract the input features from the request
        disease = request.form['disease']
        severity = request.form['severity']
        age = int(request.form['age'])
        gender = request.form['gender']
        
        # Validate input
        if disease not in label_encoders['disease'].classes_:
            return render_template('/Service/ayurvedicmedicines.html', prediction_text='Error: Invalid disease value.')
        if severity not in label_encoders['severity'].classes_:
            return render_template('/Service/ayurvedicmedicines.html', prediction_text='Error: Invalid severity value.')
        if gender not in label_encoders['gender'].classes_:
            return render_template('/Service/ayurvedicmedicines.html', prediction_text='Error: Invalid gender value.')

        # Encode the input features
        disease_encoded = label_encoders['disease'].transform([disease])[0]
        severity_encoded = label_encoders['severity'].transform([severity])[0]
        gender_encoded = label_encoders['gender'].transform([gender])[0]
        
        # Prepare the input array for the model
        input_features = [[disease_encoded, severity_encoded, age, gender_encoded]]
        
        # Predict the drug
        predicted_drug = model.predict(input_features)[0]
        
        # Generate a Google search link for more information
        more_info_link = f"https://www.google.com/search?q={predicted_drug.replace(' ', '+')}+ayurvedic+medicine"
        
        # Fetch images from Google
        image_search_url = f"https://www.google.com/search?q={predicted_drug.replace(' ', '+')}+ayurvedic+medicine&tbm=isch"
        response = requests.get(image_search_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        image_tags = soup.find_all('img')
        images = [img['src'] for img in image_tags if img['src'].startswith('http')][:5]  # Fetch top 5 images

        return render_template('/Service/ayurvedicmedicinesresult.html', 
                               predicted_drug=predicted_drug, 
                               more_info_link=more_info_link, 
                               images=images, 
                               disease=disease, 
                               severity=severity, 
                               age=age, 
                               gender=gender,user_name=user_name,
                               user_email=user_email,
                               user_image=user_image,
                               is_admin=is_admin)
    except Exception as e:
        return render_template('/Service/ayurvedicmedicines.html', prediction_text=f'Error: {str(e)}')

#================================================Ayurvedic Medicines Prediction End ===========================================================
#================================================Ayurvedic Medicines Prediction  End ===========================================================

#================================================Diet Recommendation  Start===========================================================
#================================================Diet Recommendation  Start ==========================================================

genai.configure(api_key="AIzaSyBfrXwYPsVklt3edTC5a3-fFIntv3MG7SA")

@app.route('/dietre')
def dietre():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    return render_template('/Service/dietrecommendation.html',
                          user_name=user_name,
                               user_email=user_email,
                               user_image=user_image,
                               is_admin=is_admin )

@app.route('/dietrecommend', methods=['POST'])
def dietrecommend():
    if not session.get('user_id'):
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name')
    user_email = session.get('user_email')
    user_image = session.get('user_image')
    is_admin = session.get('is_admin', False)

    age = int(request.form['age'])
    height = float(request.form['height'])
    weight = float(request.form['weight'])
    gender = request.form['gender']  # Get the gender as a string
    activity = request.form['activity']
    plan = request.form['plan']
    meals = int(request.form['meals'])
    restrictions = request.form.getlist('restrictions')  # Get a list of selected restrictions

    # Map gender strings to integer indices
    gender_map = {"male": 0, "female": 1}
    gender_index = gender_map[gender]

    # BMI Calculation
    bmi = round(weight / ((height / 100) ** 2), 1)
    bmi_category = get_bmi_category(bmi)

    # Calorie Calculation (Improved Accuracy)
    bmr = calculate_bmr(weight, height, age, gender_index)
    calories = round(bmr * calculate_activity_factor(activity))

    # Adjust calories based on weight loss/gain plan
    if plan == "lose":
        calories -= 500
    elif plan == "gain":
        calories += 500

    # Meal Recommendations using Gemini API
    prompt = f"Generate {meals} meal recommendations for a {gender} aged {age} with a {bmi_category} BMI, aiming for {calories} calories per day. Consider dietary restrictions: {restrictions}. Ensure each meal is balanced and nutritious."
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    meal_recommendations = response.text.split("\n\n")

    return render_template('/Service/dietrecommendationresult.html', bmi=bmi, bmi_category=bmi_category, calories=calories, meals_data=meal_recommendations,user_name=user_name,
                               user_email=user_email,
                               user_image=user_image,
                               is_admin=is_admin)

def get_bmi_category(bmi):
    if bmi < 18.5:
        return "Underweight"
    elif 18.5 <= bmi < 25:
        return "Normal weight"
    elif 25 <= bmi < 30:
        return "Overweight"
    else:
        return "Obesity"

def calculate_bmr(weight, height, age, gender_index):
    if gender_index == 0:  # Male
        bmr = 10 * weight + 6.25 * height - 5 * age + 5
    else:  # Female
        bmr = 10 * weight + 6.25 * height - 5 * age - 161
    return bmr

def calculate_activity_factor(activity):
    activity_factors = {
        "none": 1.2,
        "light": 1.375,
        "moderate": 1.55,
        "active": 1.725,
        "extra": 1.9
    }
    return activity_factors[activity]


#================================================Diet Recommendation End===========================================================
#================================================Diet Recommendation End===========================================================



if __name__ == '__main__':
    app.run(debug=True)
