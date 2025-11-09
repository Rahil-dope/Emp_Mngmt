from flask import Flask, render_template, request, redirect, url_for, send_file, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
import csv
import io
import os
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

app = Flask(__name__)

# Configuration using environment variables to support deployments (e.g. Vercel).
# - SECRET_KEY: set in production via environment variable for session/security
# - DATABASE_URL or SQLALCHEMY_DATABASE_URI: external DB for production (Postgres, MySQL, etc.)
# If no DATABASE_URL is provided, fall back to a local SQLite file inside `instance/` for
# local development.

# Secret key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.environ.get('FLASK_SECRET_KEY') or 'dev-key-change-me'

# Database URL: prefer SQLALCHEMY_DATABASE_URI then DATABASE_URL. For some providers
# (Heroku-like) DATABASE_URL may start with 'postgres://', which SQLAlchemy prefers
# 'postgresql://'. Normalize that automatically.
database_url = os.environ.get('SQLALCHEMY_DATABASE_URI') or os.environ.get('DATABASE_URL')
if database_url:
    # Normalize old-style postgres URL
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Use a local sqlite file inside instance/ for development
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    db_path = os.path.join(instance_path, 'attendance.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

# Common SQLAlchemy settings
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"]) 

# Models
class Agent(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='agent')
    email = db.Column(db.String(255), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    dsat = db.Column(db.Float, nullable=True)
    csat = db.Column(db.Float, nullable=True)
    review = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    login_time = db.Column(db.DateTime, nullable=False)
    logout_time = db.Column(db.DateTime, nullable=True)
    total_hours = db.Column(db.Float, nullable=True)

    agent = db.relationship('Agent', backref=db.backref('attendances', lazy=True))

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    expires_at = db.Column(db.Date, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=False)
    
    creator = db.relationship('Agent', backref=db.backref('announcements', lazy=True))

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    try:
        return Agent.query.get(int(user_id))
    except Exception:
        return None

# Template filters
def register_template_filters(app):
    @app.template_filter('in_tuple_list')
    def in_tuple_list(value, tuple_list):
        """Check if agent id exists in logged_in tuple list"""
        if not tuple_list:
            return False
        if isinstance(value, tuple):
            agent_id = value[0]
        else:
            agent_id = value.id if hasattr(value, 'id') else value
        for item in tuple_list:
            if isinstance(item, tuple) and len(item) > 0:
                if hasattr(item[0], 'id') and item[0].id == agent_id:
                    return True
            elif hasattr(item, 'id') and item.id == agent_id:
                return True
        return False

    @app.template_filter('format_time')
    def format_time(value, format='%H:%M:%S'):
        """Format time objects"""
        if value is None:
            return '-'
        try:
            return value.strftime(format)
        except:
            return str(value)

    @app.template_filter('format_date')
    def format_date(value, format='%Y-%m-%d'):
        """Format date objects"""
        if value is None:
            return 'N/A'
        try:
            return value.strftime(format)
        except:
            return str(value)

# Register template filters
register_template_filters(app)

@app.template_filter('datetime')
def datetime_filter(value, format='%Y-%m-%d %H:%M:%S'):
    """Format datetime objects"""
    if value is None:
        return ''
    if isinstance(value, datetime):
        return value.strftime(format)
    return str(value)

def init_db():
    """Initialize database and create admin user"""
    with app.app_context():
        # Create all tables (don't drop to preserve existing data)
        db.create_all()
        # Ensure email column exists (safe migration for SQLite)
        try:
            res = db.session.execute(db.text("PRAGMA table_info(agent)"))
            cols = [r[1].lower() for r in res]
            if 'email' not in cols:
                db.session.execute(db.text("ALTER TABLE agent ADD COLUMN email VARCHAR(255)"))
                db.session.commit()
        except Exception as e:
            db.session.rollback()
        
        # Create default admin user if not exists
        try:
            admin = Agent.query.filter_by(name='admin').first()
            if not admin:
                admin = Agent(name='admin', role='admin')
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("Created admin user successfully")
        except Exception as e:
            print(f"Error creating admin user: {e}")
            db.session.rollback()

# Initialize database
init_db()

# Routes
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '')
        # role selection removed; admin exists by seed only
        
        if not name or not password:
            flash('Please enter name and password', 'warning')
            return redirect(url_for('login'))
            
        agent = Agent.query.filter_by(name=name).first()
        if agent:
            if not agent.check_password(password):
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))
        else:
            # Do not auto-create via login
            flash('Account not found. Please create an account.', 'info')
            return redirect(url_for('register'))
            
        login_user(agent)
        if agent.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('agent_dashboard'))
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not name or not email or not password or not confirm:
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))

        # Basic email validation
        try:
            from email_validator import validate_email, EmailNotValidError
            validate_email(email)
        except Exception:
            flash('Please enter a valid email address', 'warning')
            return redirect(url_for('register'))

        # Stronger password rules
        if len(password) < 8 or password.lower() == password or not any(c.isdigit() for c in password):
            flash('Password must be 8+ chars, include a number and a capital letter', 'warning')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        existing = Agent.query.filter_by(name=name).first()
        if existing:
            flash('An account with that name already exists', 'warning')
            return redirect(url_for('register'))
        if email and Agent.query.filter_by(email=email).first():
            flash('Email is already registered', 'warning')
            return redirect(url_for('register'))

        try:
            agent = Agent(name=name, role='agent', email=email)
            agent.set_password(password)
            db.session.add(agent)
            db.session.commit()
            login_user(agent)
            flash('Account created successfully. Welcome!', 'success')
            return redirect(url_for('agent_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed: %s' % str(e), 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/admin/create_agent', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
@login_required
def admin_create_agent():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        csat = request.form.get('csat')
        dsat = request.form.get('dsat')
        review = request.form.get('review')

        if not name or not email or not password:
            flash('Name, email and password are required', 'danger')
            return redirect(url_for('admin_create_agent'))
        try:
            from email_validator import validate_email
            validate_email(email)
        except Exception:
            flash('Please enter a valid email address', 'warning')
            return redirect(url_for('admin_create_agent'))
        if len(password) < 8 or password.lower() == password or not any(c.isdigit() for c in password):
            flash('Password must be 8+ chars, include a number and a capital letter', 'warning')
            return redirect(url_for('admin_create_agent'))
        if Agent.query.filter((Agent.name==name) | (Agent.email==email)).first():
            flash('Name or email already exists', 'warning')
            return redirect(url_for('admin_create_agent'))
        try:
            agent = Agent(name=name, role='agent', email=email)
            agent.set_password(password)
            if csat:
                agent.csat = float(csat)
            if dsat:
                agent.dsat = float(dsat)
            agent.review = review.strip() if review else None
            db.session.add(agent)
            db.session.commit()
            flash('Agent created successfully', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to create agent: %s' % str(e), 'danger')
            return redirect(url_for('admin_create_agent'))
    return render_template('create_agent.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/agent')
@login_required
def agent_dashboard():
    if current_user.role != 'agent':
        return redirect(url_for('login'))
    agent = Agent.query.get(current_user.id)
    attendances = Attendance.query.filter_by(agent_id=agent.id).order_by(Attendance.date.desc(), Attendance.login_time.desc()).all()
    active_session = Attendance.query.filter_by(agent_id=agent.id, logout_time=None).order_by(Attendance.id.desc()).first()
    return render_template('agent_dashboard.html', agent=agent, attendances=attendances, active_session=active_session)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    agents = Agent.query.order_by(Agent.name).all()

    # Optional date filters for attendance list
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    query = Attendance.query
    if date_from:
        try:
            df = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(Attendance.date >= df)
        except ValueError:
            pass
    if date_to:
        try:
            dt = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(Attendance.date <= dt)
        except ValueError:
            pass
    attendances = query.order_by(Attendance.date.desc(), Attendance.login_time.desc()).limit(200).all()
    avg_csat = db.session.query(db.func.avg(Agent.csat)).scalar() or 0
    avg_dsat = db.session.query(db.func.avg(Agent.dsat)).scalar() or 0
    logged_in = db.session.query(Agent, Attendance).join(Attendance).filter(Attendance.logout_time==None).all()
    return render_template('admin_dashboard.html', agents=agents, attendances=attendances, avg_csat=avg_csat, avg_dsat=avg_dsat, logged_in=logged_in, date_from=date_from or '', date_to=date_to or '')

@app.route('/time_in', methods=['POST'])
@login_required
def time_in():
    if current_user.role != 'agent':
        return redirect(url_for('login'))
    agent_id = current_user.id
    now = datetime.now()
    today = now.date()
    last = Attendance.query.filter_by(agent_id=agent_id).order_by(Attendance.id.desc()).first()
    if last and last.logout_time is None:
        flash('You are already timed in. Please Time Out first.', 'warning')
        return redirect(url_for('agent_dashboard'))
    a = Attendance(agent_id=agent_id, date=today, login_time=now)
    db.session.add(a)
    db.session.commit()
    flash('Time In recorded at %s' % now.strftime('%Y-%m-%d %H:%M:%S'), 'success')
    return redirect(url_for('agent_dashboard'))

@app.route('/time_out', methods=['POST'])
@login_required
def time_out():
    if current_user.role != 'agent':
        return redirect(url_for('login'))
    agent_id = current_user.id
    now = datetime.now()
    last = Attendance.query.filter_by(agent_id=agent_id, logout_time=None).order_by(Attendance.id.desc()).first()
    if not last:
        flash('No active Time In found. Please Time In first.', 'warning')
        return redirect(url_for('agent_dashboard'))
    last.logout_time = now
    duration = now - last.login_time
    last.total_hours = round(duration.total_seconds() / 3600, 2)
    db.session.commit()
    flash('Time Out recorded at %s (Total hours: %s)' % (now.strftime('%Y-%m-%d %H:%M:%S'), last.total_hours), 'success')
    return redirect(url_for('agent_dashboard'))

@app.route('/agent/<int:agent_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_agent(agent_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    agent = Agent.query.get_or_404(agent_id)
    if request.method == 'POST':
        try:
            csat = request.form.get('csat')
            dsat = request.form.get('dsat')
            review = request.form.get('review')
            
            # Validate CSAT/DSAT (0-10 range)
            if csat:
                csat_val = float(csat)
                if csat_val < 0 or csat_val > 10:
                    flash('CSAT must be between 0 and 10', 'danger')
                    return render_template('edit_agent.html', agent=agent)
                agent.csat = csat_val
            else:
                agent.csat = None
                
            if dsat:
                dsat_val = float(dsat)
                if dsat_val < 0 or dsat_val > 10:
                    flash('DSAT must be between 0 and 10', 'danger')
                    return render_template('edit_agent.html', agent=agent)
                agent.dsat = dsat_val
            else:
                agent.dsat = None
                
            agent.review = review.strip() if review else None
            db.session.commit()
            flash('Agent performance updated successfully', 'success')
            return redirect(url_for('admin_dashboard'))
        except ValueError:
            flash('Invalid number format for CSAT/DSAT', 'danger')
        except Exception as e:
            flash('Error updating agent: %s' % str(e), 'danger')
            db.session.rollback()
    return render_template('edit_agent.html', agent=agent)

@app.route('/my_profile')
@login_required
def my_profile():
    agent = Agent.query.get_or_404(current_user.id)
    attendances = Attendance.query.filter_by(agent_id=agent.id).order_by(
        Attendance.date.desc(), Attendance.login_time.desc()).limit(50).all()
    return render_template('agent_profile.html', agent=agent, attendances=attendances)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'danger')
        return redirect(url_for('my_profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('my_profile'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters long', 'danger')
        return redirect(url_for('my_profile'))
    
    agent = Agent.query.get_or_404(current_user.id)
    if not agent.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('my_profile'))
    
    agent.set_password(new_password)
    db.session.commit()
    flash('Password updated successfully', 'success')
    return redirect(url_for('my_profile'))

@app.route('/announcements', methods=['GET', 'POST'])
@login_required
def announcements():
    if request.method == 'POST' and current_user.role == 'admin':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        expires_at_str = request.form.get('expires_at')
        
        if not title or not content:
            flash('Title and content are required', 'danger')
            return redirect(url_for('announcements'))
        
        expires_at = None
        if expires_at_str:
            try:
                expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid date format', 'warning')
        
        announcement = Announcement(
            title=title,
            content=content,
            expires_at=expires_at,
            created_by=current_user.id
        )
        db.session.add(announcement)
        db.session.commit()
        flash('Announcement posted successfully', 'success')
        return redirect(url_for('announcements'))
    
    # Get active announcements (not expired)
    now = date.today()
    announcements_list = Announcement.query.filter(
        (Announcement.expires_at.is_(None)) | (Announcement.expires_at >= now)
    ).order_by(Announcement.created_at.desc()).all()
    
    return render_template('announcements.html', 
                         announcements=announcements_list, 
                         now=now)

@app.route('/export')
@login_required
def export_data():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    format_type = request.args.get('format', 'csv').lower()
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    # Build query
    query = db.session.query(Attendance, Agent).join(Agent)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(Attendance.date >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(Attendance.date <= date_to_obj)
        except ValueError:
            pass
    
    records = query.order_by(Attendance.date.desc(), Attendance.login_time.desc()).all()
    
    if format_type == 'xlsx' and OPENPYXL_AVAILABLE:
        wb = Workbook()
        ws = wb.active
        ws.title = "Attendance Report"
        
        # Header row
        headers = ['Agent Name', 'Date', 'Login Time', 'Logout Time', 'Total Hours']
        ws.append(headers)
        
        # Style header row
        for cell in ws[1]:
            cell.font = Font(bold=True)
            cell.alignment = Alignment(horizontal='center')
        
        # Data rows
        for att, agent in records:
            ws.append([
                agent.name,
                att.date.strftime('%Y-%m-%d'),
                att.login_time.strftime('%H:%M:%S') if att.login_time else '',
                att.logout_time.strftime('%H:%M:%S') if att.logout_time else '',
                round(att.total_hours, 2) if att.total_hours else ''
            ])
        
        # Save to BytesIO
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        
        filename = f'attendance_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        as_attachment=True, download_name=filename)
    
    else:  # CSV format
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['Agent Name', 'Date', 'Login Time', 'Logout Time', 'Total Hours'])
        
        # Data rows
        for att, agent in records:
            writer.writerow([
                agent.name,
                att.date.strftime('%Y-%m-%d'),
                att.login_time.strftime('%H:%M:%S') if att.login_time else '',
                att.logout_time.strftime('%H:%M:%S') if att.logout_time else '',
                round(att.total_hours, 2) if att.total_hours else ''
            ])
        
        output.seek(0)
        filename = f'attendance_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )

@app.route('/export_performance')
@login_required
def export_performance():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Agent Name', 'CSAT', 'DSAT', 'Review'])
    for a in Agent.query.order_by(Agent.name).all():
        writer.writerow([
            a.name,
            ('%.2f' % a.csat) if a.csat is not None else '',
            ('%.2f' % a.dsat) if a.dsat is not None else '',
            (a.review or '').replace('\n', ' ').strip()
        ])
    output.seek(0)
    filename = f'performance_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

@app.route('/api/stats')
@login_required
def api_stats():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    avg_csat = db.session.query(db.func.avg(Agent.csat)).scalar() or 0
    avg_dsat = db.session.query(db.func.avg(Agent.dsat)).scalar() or 0
    total_agents = Agent.query.filter_by(role='agent').count()
    logged_in_count = db.session.query(Agent).join(Attendance).filter(
        Attendance.logout_time.is_(None)
    ).distinct().count()
    
    today_attendances = Attendance.query.filter(
        Attendance.date == date.today()
    ).count()
    
    return jsonify({
        'avg_csat': round(avg_csat, 2),
        'avg_dsat': round(avg_dsat, 2),
        'total_agents': total_agents,
        'logged_in': logged_in_count,
        'today_attendances': today_attendances
    })

@app.route('/api/agent/me')
@login_required
def api_agent_me():
    return jsonify({
        'id': current_user.id,
        'name': current_user.name,
        'csat': current_user.csat,
        'dsat': current_user.dsat,
        'review': current_user.review
    })

@app.route('/admin_login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def admin_login():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '')
        if not name or not password:
            flash('Please enter name and password', 'warning')
            return redirect(url_for('admin_login'))
        agent = Agent.query.filter_by(name=name).first()
        if not agent or agent.role != 'admin' or not agent.check_password(password):
            flash('Invalid admin credentials', 'danger')
            return redirect(url_for('admin_login'))
        login_user(agent)
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/agent/<int:agent_id>/history')
@login_required
def agent_history(agent_id):
    if current_user.role != 'admin' and current_user.id != agent_id:
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    agent = Agent.query.get_or_404(agent_id)
    attendances = Attendance.query.filter_by(agent_id=agent_id).order_by(
        Attendance.date.desc(), Attendance.login_time.desc()).all()
    
    # Calculate statistics
    total_hours = sum(a.total_hours for a in attendances if a.total_hours)
    completed_sessions = [a for a in attendances if a.total_hours]
    avg_hours = total_hours / len(completed_sessions) if completed_sessions else 0
    
    return render_template('agent_history.html', 
                         agent=agent, 
                         attendances=attendances,
                         total_hours=total_hours,
                         avg_hours=avg_hours)

if __name__ == '__main__':
    app.run(debug=True)