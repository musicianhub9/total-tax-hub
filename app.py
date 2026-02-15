from flask import Flask, request, jsonify, session, send_from_directory, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__, static_folder='static', template_folder='templates')
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise ValueError("SECRET_KEY is not set!")

app.config['SECRET_KEY'] = secret_key


database_url = os.getenv("DATABASE_URL")

if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

if not database_url:
    raise ValueError("DATABASE_URL is not set!")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url




app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = '/data/uploads'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'it_returns'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'gst_returns'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'gst_registrations'), exist_ok=True)

CORS(app, supports_credentials=True)
db = SQLAlchemy(app)

# ==================== Database Models ====================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobile = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    login_history = db.relationship('LoginHistory', backref='user', lazy=True)
    pan_records = db.relationship('PANRecord', backref='user', lazy=True)
    gst_registrations = db.relationship('GSTRegistration', backref='user', lazy=True)
    it_returns = db.relationship('IncomeTaxReturn', backref='user', lazy=True)
    gst_returns = db.relationship('GSTReturn', backref='user', lazy=True)
    queries = db.relationship('TaxQuery', backref='user', lazy=True)
    chat_messages = db.relationship('ChatMessage', backref='user', lazy=True)

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    added_by = db.Column(db.String(100))
    added_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    device = db.Column(db.String(200))
    user_agent = db.Column(db.String(500))

class PANRecord(db.Model):
    __tablename__ = 'pan_records'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100))
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    father_name = db.Column(db.String(100))
    pan = db.Column(db.String(20), unique=True)
    dob = db.Column(db.String(20))
    plot_no = db.Column(db.String(100))
    building_name = db.Column(db.String(200))
    street_no = db.Column(db.String(100))
    area = db.Column(db.String(200))
    city = db.Column(db.String(100))
    district = db.Column(db.String(100))
    state = db.Column(db.String(100))
    pin = db.Column(db.String(10))
    mobile = db.Column(db.String(20))
    email = db.Column(db.String(100))
    income_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class GSTRegistration(db.Model):
    __tablename__ = 'gst_registrations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    gst_number = db.Column(db.String(20), unique=True)
    business_name = db.Column(db.String(200))
    business_type = db.Column(db.String(50))
    main_person = db.Column(db.String(100))
    address = db.Column(db.String(500))
    pan_no = db.Column(db.String(20))
    udyam_no = db.Column(db.String(20))
    bank_acc_no = db.Column(db.String(50))
    ifsc_code = db.Column(db.String(20))
    documents = db.Column(db.Text)  # JSON string of file names
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class IncomeTaxReturn(db.Model):
    __tablename__ = 'income_tax_returns'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    pan_record_id = db.Column(db.Integer, db.ForeignKey('pan_records.id'))
    bank_account = db.Column(db.String(50))
    ifsc_code = db.Column(db.String(20))
    financial_year = db.Column(db.String(20))
    assessment_year = db.Column(db.String(20))
    income_sources = db.Column(db.Text)  # JSON string
    form16_file = db.Column(db.String(200))
    other_docs = db.Column(db.Text)  # JSON string
    status = db.Column(db.String(20), default='Filed')
    filing_date = db.Column(db.DateTime, default=datetime.utcnow)

class GSTReturn(db.Model):
    __tablename__ = 'gst_returns'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    gst_registration_id = db.Column(db.Integer, db.ForeignKey('gst_registrations.id'))
    financial_year = db.Column(db.String(20))
    month = db.Column(db.String(20))
    documents = db.Column(db.Text)  # JSON string
    status = db.Column(db.String(20), default='Filed')
    filing_date = db.Column(db.DateTime, default=datetime.utcnow)

class TaxQuery(db.Model):
    __tablename__ = 'tax_queries'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    mobile = db.Column(db.String(20))
    subject = db.Column(db.String(200))
    query_text = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    response = db.Column(db.Text)
    responded_at = db.Column(db.DateTime)

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'))
    message = db.Column(db.Text)
    sender = db.Column(db.String(20))  # 'user' or 'admin'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class News(db.Model):
    __tablename__ = 'news'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    published_date = db.Column(db.DateTime, default=datetime.utcnow)
    published_by = db.Column(db.Integer, db.ForeignKey('admins.id'))

# ==================== Helper Functions ====================

def init_db():
    """Initialize database with default admin"""
    with app.app_context():
        db.create_all()
        
        # Create default super admin if not exists
        if not Admin.query.filter_by(email='muneshlife@gmail.com').first():
            default_admin = Admin(
                email='muneshlife@gmail.com',
                password=generate_password_hash('1234567890'),
                is_super_admin=True,
                added_by='System',
                last_activity=datetime.utcnow()
            )
            db.session.add(default_admin)
            db.session.commit()

def get_client_info():
    """Get client IP and user agent"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    
    # Simple device detection
    device = 'Desktop'
    if 'Mobile' in user_agent or 'Android' in user_agent or 'iPhone' in user_agent:
        device = 'Mobile'
    
    return ip, device, user_agent

def save_uploaded_files(files, subfolder):
    """Save uploaded files and return list of filenames"""
    saved_files = []
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
    os.makedirs(upload_path, exist_ok=True)
    
    for file in files:
        if file and file.filename:
            filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
            file.save(os.path.join(upload_path, filename))
            saved_files.append(filename)
    return saved_files

# ==================== Frontend Routes ====================

@app.route('/')
def serve_frontend():
    return send_from_directory('templates', 'frontend.html')

@app.route('/admin')
def serve_admin():
    return send_from_directory('templates', 'admin_panel.html')

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# ==================== File Download Routes ====================

@app.route('/api/download/<file_type>/<filename>')
def download_file(file_type, filename):
    """Download uploaded files"""
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Define subfolders for different file types
    subfolders = {
        'it_return': 'it_returns',
        'gst_return': 'gst_returns',
        'gst_registration': 'gst_registrations'
    }
    
    subfolder = subfolders.get(file_type)
    if not subfolder:
        return jsonify({'success': False, 'message': 'Invalid file type'}), 400
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder, filename)
    
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'File not found'}), 404
    
    return send_file(file_path, as_attachment=True, download_name=filename)

# ==================== API Routes ====================

# ---------- User Authentication ----------
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email').strip().lower()
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        hashed_password = generate_password_hash(data.get('password'))
        new_user = User(
            name=data.get('name'),
            email=email,
            mobile=data.get('mobile'),
            password=hashed_password
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email').strip().lower()
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            session.permanent = True
            
            # Record login history
            ip, device, user_agent = get_client_info()
            login_record = LoginHistory(
                user_id=user.id,
                ip_address=ip,
                device=device,
                user_agent=user_agent
            )
            db.session.add(login_record)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'mobile': user.mobile
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        return jsonify({
            'success': True,
            'authenticated': True,
            'user': {
                'id': session['user_id'],
                'name': session['user_name'],
                'email': session['user_email']
            }
        })
    return jsonify({'success': True, 'authenticated': False})

# ---------- Admin Authentication ----------
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        email = data.get('email').strip().lower()
        password = data.get('password')
        
        admin = Admin.query.filter_by(email=email).first()
        
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['admin_email'] = admin.email
            session['admin_is_super'] = admin.is_super_admin
            
            # Update last activity
            admin.last_activity = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'admin': {
                    'id': admin.id,
                    'email': admin.email,
                    'is_super_admin': admin.is_super_admin
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_email', None)
    session.pop('admin_is_super', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/admin/check-auth', methods=['GET'])
def admin_check_auth():
    if 'admin_id' in session:
        return jsonify({
            'success': True,
            'authenticated': True,
            'admin': {
                'id': session['admin_id'],
                'email': session['admin_email'],
                'is_super_admin': session.get('admin_is_super', False)
            }
        })
    return jsonify({'success': True, 'authenticated': False})

# ---------- Admin Management (Super Admin Only) ----------
@app.route('/api/admin/add', methods=['POST'])
def add_admin():
    if not session.get('admin_is_super'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        data = request.json
        email = data.get('email').strip().lower()
        
        if Admin.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Admin already exists'}), 400
        
        new_admin = Admin(
            email=email,
            password=generate_password_hash(data.get('password')),
            is_super_admin=False,
            added_by=session.get('admin_email'),
            added_date=datetime.utcnow()
        )
        
        db.session.add(new_admin)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Admin added successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/remove/<int:admin_id>', methods=['DELETE'])
def remove_admin(admin_id):
    if not session.get('admin_is_super'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        admin = Admin.query.get(admin_id)
        if admin and not admin.is_super_admin:
            db.session.delete(admin)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Admin removed successfully'})
        return jsonify({'success': False, 'message': 'Admin not found or cannot be removed'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admins', methods=['GET'])
def get_admins():
    if not session.get('admin_id'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    admins = Admin.query.all()
    admin_list = []
    for admin in admins:
        admin_list.append({
            'id': admin.id,
            'email': admin.email,
            'is_super_admin': admin.is_super_admin,
            'added_by': admin.added_by,
            'added_date': admin.added_date.strftime('%Y-%m-%d') if admin.added_date else '',
            'last_activity': admin.last_activity.strftime('%Y-%m-%d %H:%M') if admin.last_activity else 'Never'
        })
    
    return jsonify({'success': True, 'admins': admin_list})

# ---------- PAN Records ----------
@app.route('/api/pan/add', methods=['POST'])
def add_pan():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login'}), 401
    
    try:
        data = request.json
        new_pan = PANRecord(
            user_id=session['user_id'],
            name=data.get('name'),
            middle_name=data.get('middleName', ''),
            last_name=data.get('lastName'),
            father_name=data.get('fatherName'),
            pan=data.get('pan'),
            dob=data.get('dob'),
            plot_no=data.get('plotNo'),
            building_name=data.get('buildingName'),
            street_no=data.get('streetNo'),
            area=data.get('area'),
            city=data.get('city'),
            district=data.get('district'),
            state=data.get('state'),
            pin=data.get('pin'),
            mobile=data.get('mobile'),
            email=data.get('email'),
            income_type=data.get('incomeType')
        )
        
        db.session.add(new_pan)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'PAN details saved successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/pan/search', methods=['GET'])
def search_pan():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login'}), 401
    
    pan = request.args.get('pan', '').upper()
    record = PANRecord.query.filter_by(pan=pan).first()
    
    if record:
        return jsonify({
            'success': True,
            'record': {
                'id': record.id,
                'pan': record.pan,
                'name': record.name,
                'middleName': record.middle_name,
                'lastName': record.last_name,
                'fatherName': record.father_name,
                'dob': record.dob,
                'mobile': record.mobile,
                'email': record.email,
                'incomeType': record.income_type,
                'address': f"{record.plot_no}, {record.building_name}, {record.city}, {record.state} - {record.pin}"
            }
        })
    
    return jsonify({'success': False, 'message': 'PAN not found'}), 404

@app.route('/api/user/pan-records', methods=['GET'])
def get_user_pan_records():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    records = PANRecord.query.filter_by(user_id=session['user_id']).all()
    record_list = []
    for record in records:
        record_list.append({
            'id': record.id,
            'pan': record.pan,
            'name': f"{record.name} {record.middle_name} {record.last_name}",
            'income_type': record.income_type,
            'created_at': record.created_at.strftime('%Y-%m-%d')
        })
    
    return jsonify({'success': True, 'records': record_list})

# ---------- GST Registration ----------
@app.route('/api/gst/register', methods=['POST'])
def register_gst():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login'}), 401
    
    try:
        data = request.json
        # Handle file uploads if any
        documents = []
        if 'documents' in request.files:
            files = request.files.getlist('documents')
            documents = save_uploaded_files(files, 'gst_registrations')
        
        new_gst = GSTRegistration(
            user_id=session['user_id'],
            gst_number=data.get('gstNumber'),
            business_name=data.get('businessName'),
            business_type=data.get('businessType'),
            main_person=data.get('mainPerson'),
            address=data.get('address'),
            pan_no=data.get('panNo'),
            udyam_no=data.get('udyamNo'),
            bank_acc_no=data.get('bankAccNo'),
            ifsc_code=data.get('ifscCode'),
            documents=json.dumps(documents if documents else data.get('documents', []))
        )
        
        db.session.add(new_gst)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'GST Registration saved successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/user/gst-registrations', methods=['GET'])
def get_user_gst_registrations():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    registrations = GSTRegistration.query.filter_by(user_id=session['user_id']).all()
    reg_list = []
    for reg in registrations:
        reg_list.append({
            'id': reg.id,
            'gstNumber': reg.gst_number,
            'businessName': reg.business_name,
            'businessType': reg.business_type,
            'mainPerson': reg.main_person,
            'address': reg.address,
            'panNo': reg.pan_no,
            'udyamNo': reg.udyam_no,
            'bankAccNo': reg.bank_acc_no,
            'ifscCode': reg.ifsc_code,
            'documents': json.loads(reg.documents) if reg.documents else [],
            'created_at': reg.created_at.strftime('%Y-%m-%d')
        })
    
    return jsonify({'success': True, 'registrations': reg_list})

# ---------- Income Tax Return ----------
@app.route('/api/it-return/file', methods=['POST'])
def file_it_return():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login'}), 401
    
    try:
        data = request.json
        form16_file = data.get('form16File')
        other_docs = data.get('otherDocs', [])
        
        new_return = IncomeTaxReturn(
            user_id=session['user_id'],
            pan_record_id=data.get('panRecordId'),
            bank_account=data.get('bankAccount'),
            ifsc_code=data.get('ifscCode'),
            financial_year=data.get('financialYear'),
            assessment_year=data.get('assessmentYear'),
            income_sources=json.dumps(data.get('incomeSources', [])),
            form16_file=form16_file,
            other_docs=json.dumps(other_docs),
            status='Filed'
        )
        
        db.session.add(new_return)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Income Tax Return filed successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------- GST Return ----------
@app.route('/api/gst-return/file', methods=['POST'])
def file_gst_return():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login'}), 401
    
    try:
        data = request.json
        documents = data.get('documents', [])
        
        new_return = GSTReturn(
            user_id=session['user_id'],
            gst_registration_id=data.get('gstRegistrationId'),
            financial_year=data.get('financialYear'),
            month=data.get('month'),
            documents=json.dumps(documents),
            status='Filed'
        )
        
        db.session.add(new_return)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'GST Return filed successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------- Tax Query ----------
@app.route('/api/query/submit', methods=['POST'])
def submit_query():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login'}), 401
    
    try:
        data = request.json
        new_query = TaxQuery(
            user_id=session['user_id'],
            name=data.get('name'),
            email=data.get('email'),
            mobile=data.get('mobile'),
            subject=data.get('subject'),
            query_text=data.get('query'),
            status='Pending'
        )
        
        db.session.add(new_query)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Query submitted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------- Chat Messages ----------
@app.route('/api/chat/messages/<int:user_id>', methods=['GET'])
def get_chat_messages(user_id):
    if 'admin_id' not in session and 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    messages = ChatMessage.query.filter_by(user_id=user_id).order_by(ChatMessage.timestamp).all()
    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg.id,
            'message': msg.message,
            'sender': msg.sender,
            'timestamp': msg.timestamp.strftime('%H:%M'),
            'date': msg.timestamp.strftime('%Y-%m-%d'),
            'is_read': msg.is_read
        })
    
    return jsonify({'success': True, 'messages': message_list})

@app.route('/api/chat/send', methods=['POST'])
def send_chat_message():
    if 'admin_id' not in session and 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        user_id = data.get('userId')
        
        new_message = ChatMessage(
            user_id=user_id,
            admin_id=session.get('admin_id'),
            message=data.get('message'),
            sender='admin' if 'admin_id' in session else 'user'
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Message sent'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------- Admin Data Fetch Routes ----------
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'mobile': user.mobile,
            'regDate': user.created_at.strftime('%Y-%m-%d')
        })
    
    return jsonify({'success': True, 'users': user_list})

@app.route('/api/admin/user/<int:user_id>/details', methods=['GET'])
def get_user_details(user_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Get PAN records with all details
    pan_records = []
    for pan in user.pan_records:
        pan_records.append({
            'id': pan.id,
            'pan': pan.pan,
            'name': pan.name,
            'middle_name': pan.middle_name,
            'last_name': pan.last_name,
            'full_name': f"{pan.name} {pan.middle_name} {pan.last_name}".strip(),
            'father_name': pan.father_name,
            'dob': pan.dob,
            'plot_no': pan.plot_no,
            'building_name': pan.building_name,
            'street_no': pan.street_no,
            'area': pan.area,
            'city': pan.city,
            'district': pan.district,
            'state': pan.state,
            'pin': pan.pin,
            'full_address': f"{pan.plot_no}, {pan.building_name}, {pan.street_no}, {pan.area}, {pan.city}, {pan.district}, {pan.state} - {pan.pin}",
            'mobile': pan.mobile,
            'email': pan.email,
            'income_type': pan.income_type,
            'created_at': pan.created_at.strftime('%Y-%m-%d')
        })
    
    # Get GST registrations with all details
    gst_registrations = []
    for gst in user.gst_registrations:
        gst_registrations.append({
            'id': gst.id,
            'gst_number': gst.gst_number,
            'business_name': gst.business_name,
            'business_type': gst.business_type,
            'main_person': gst.main_person,
            'address': gst.address,
            'pan_no': gst.pan_no,
            'udyam_no': gst.udyam_no,
            'bank_acc_no': gst.bank_acc_no,
            'ifsc_code': gst.ifsc_code,
            'documents': json.loads(gst.documents) if gst.documents else [],
            'created_at': gst.created_at.strftime('%Y-%m-%d')
        })
    
    # Get IT returns with all details including PAN record info
    it_returns = []
    for ret in user.it_returns:
        pan_info = None
        if ret.pan_record_id:
            pan = PANRecord.query.get(ret.pan_record_id)
            if pan:
                pan_info = {
                    'pan': pan.pan,
                    'name': f"{pan.name} {pan.middle_name} {pan.last_name}".strip(),
                    'income_type': pan.income_type
                }
        
        it_returns.append({
            'id': ret.id,
            'bank_account': ret.bank_account,
            'ifsc_code': ret.ifsc_code,
            'financial_year': ret.financial_year,
            'assessment_year': ret.assessment_year,
            'income_sources': json.loads(ret.income_sources) if ret.income_sources else [],
            'form16_file': ret.form16_file,
            'other_docs': json.loads(ret.other_docs) if ret.other_docs else [],
            'status': ret.status,
            'filing_date': ret.filing_date.strftime('%Y-%m-%d %H:%M'),
            'pan_info': pan_info
        })
    
    # Get GST returns with all details including GST registration info
    gst_returns = []
    for ret in user.gst_returns:
        gst_info = None
        if ret.gst_registration_id:
            gst = GSTRegistration.query.get(ret.gst_registration_id)
            if gst:
                gst_info = {
                    'gst_number': gst.gst_number,
                    'business_name': gst.business_name,
                    'business_type': gst.business_type
                }
        
        gst_returns.append({
            'id': ret.id,
            'financial_year': ret.financial_year,
            'month': ret.month,
            'documents': json.loads(ret.documents) if ret.documents else [],
            'status': ret.status,
            'filing_date': ret.filing_date.strftime('%Y-%m-%d %H:%M'),
            'gst_info': gst_info
        })
    
    # Get login history
    login_history = []
    for login in user.login_history:
        login_history.append({
            'date': login.login_time.strftime('%Y-%m-%d %H:%M'),
            'ip_address': login.ip_address,
            'device': login.device
        })
    
    # Get queries
    queries = []
    for query in user.queries:
        queries.append({
            'id': query.id,
            'subject': query.subject,
            'query_text': query.query_text,
            'status': query.status,
            'created_at': query.created_at.strftime('%Y-%m-%d %H:%M'),
            'response': query.response,
            'responded_at': query.responded_at.strftime('%Y-%m-%d %H:%M') if query.responded_at else None
        })
    
    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'mobile': user.mobile,
            'regDate': user.created_at.strftime('%Y-%m-%d')
        },
        'pan_records': pan_records,
        'gst_registrations': gst_registrations,
        'it_returns': it_returns,
        'gst_returns': gst_returns,
        'login_history': login_history,
        'queries': queries
    })

@app.route('/api/admin/it-return/<int:return_id>/details', methods=['GET'])
def get_it_return_details(return_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    it_return = IncomeTaxReturn.query.get(return_id)
    if not it_return:
        return jsonify({'success': False, 'message': 'IT Return not found'}), 404
    
    # Get user info
    user = User.query.get(it_return.user_id)
    
    # Get PAN record if exists
    pan_info = None
    if it_return.pan_record_id:
        pan = PANRecord.query.get(it_return.pan_record_id)
        if pan:
            pan_info = {
                'pan': pan.pan,
                'name': pan.name,
                'middle_name': pan.middle_name,
                'last_name': pan.last_name,
                'father_name': pan.father_name,
                'dob': pan.dob,
                'mobile': pan.mobile,
                'email': pan.email,
                'income_type': pan.income_type,
                'address': f"{pan.plot_no}, {pan.building_name}, {pan.city}, {pan.state} - {pan.pin}"
            }
    
    return jsonify({
        'success': True,
        'it_return': {
            'id': it_return.id,
            'user_id': it_return.user_id,
            'user_name': user.name if user else None,
            'user_email': user.email if user else None,
            'bank_account': it_return.bank_account,
            'ifsc_code': it_return.ifsc_code,
            'financial_year': it_return.financial_year,
            'assessment_year': it_return.assessment_year,
            'income_sources': json.loads(it_return.income_sources) if it_return.income_sources else [],
            'form16_file': it_return.form16_file,
            'other_docs': json.loads(it_return.other_docs) if it_return.other_docs else [],
            'status': it_return.status,
            'filing_date': it_return.filing_date.strftime('%Y-%m-%d %H:%M'),
            'pan_info': pan_info
        }
    })

@app.route('/api/admin/gst-return/<int:return_id>/details', methods=['GET'])
def get_gst_return_details(return_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    gst_return = GSTReturn.query.get(return_id)
    if not gst_return:
        return jsonify({'success': False, 'message': 'GST Return not found'}), 404
    
    # Get user info
    user = User.query.get(gst_return.user_id)
    
    # Get GST registration if exists
    gst_info = None
    if gst_return.gst_registration_id:
        gst = GSTRegistration.query.get(gst_return.gst_registration_id)
        if gst:
            gst_info = {
                'gst_number': gst.gst_number,
                'business_name': gst.business_name,
                'business_type': gst.business_type,
                'main_person': gst.main_person,
                'address': gst.address,
                'pan_no': gst.pan_no,
                'udyam_no': gst.udyam_no,
                'bank_acc_no': gst.bank_acc_no,
                'ifsc_code': gst.ifsc_code,
                'documents': json.loads(gst.documents) if gst.documents else []
            }
    
    return jsonify({
        'success': True,
        'gst_return': {
            'id': gst_return.id,
            'user_id': gst_return.user_id,
            'user_name': user.name if user else None,
            'user_email': user.email if user else None,
            'financial_year': gst_return.financial_year,
            'month': gst_return.month,
            'documents': json.loads(gst_return.documents) if gst_return.documents else [],
            'status': gst_return.status,
            'filing_date': gst_return.filing_date.strftime('%Y-%m-%d %H:%M'),
            'gst_info': gst_info
        }
    })

@app.route('/api/admin/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    total_users = User.query.count()
    pending_queries = TaxQuery.query.filter_by(status='Pending').count()
    active_admins = Admin.query.count()
    today_logins = LoginHistory.query.filter(
        LoginHistory.login_time >= datetime.utcnow().date()
    ).count()
    total_it_returns = IncomeTaxReturn.query.count()
    total_gst_returns = GSTReturn.query.count()
    
    return jsonify({
        'success': True,
        'stats': {
            'total_users': total_users,
            'pending_queries': pending_queries,
            'active_admins': active_admins,
            'today_logins': today_logins,
            'total_it_returns': total_it_returns,
            'total_gst_returns': total_gst_returns
        }
    })

# ==================== Initialize Database ====================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Create default admin if not exists
        if not Admin.query.filter_by(email='muneshlife@gmail.com').first():
            default_admin = Admin(
                email='muneshlife@gmail.com',
                password=generate_password_hash('1234567890'),
                is_super_admin=True,
                added_by='System',
                last_activity=datetime.utcnow()
            )
            db.session.add(default_admin)
            db.session.commit()

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
