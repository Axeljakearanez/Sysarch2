from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'ccs_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ccs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'webp'}

db = SQLAlchemy(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_number = db.Column(db.String(20), unique=True, nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    course = db.Column(db.String(20), nullable=False)
    course_level = db.Column(db.String(5), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200))
    profile_pic = db.Column(db.String(200), default='default.png')


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


with app.app_context():
    db.create_all()

    existing_admin = Admin.query.filter_by(username='admin').first()
    if not existing_admin:
        admin = Admin(
            username='admin',
            password=generate_password_hash('admin123')
        )
        db.session.add(admin)
        db.session.commit()


def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    )


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        id_number = request.form.get('id_number', '').strip()
        password = request.form.get('password', '').strip()

        # admin login
        admin = Admin.query.filter_by(username=id_number).first()
        if admin and check_password_hash(admin.password, password):
            session.clear()
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            return redirect(url_for('admin_dashboard'))

        # student login
        student = Student.query.filter_by(id_number=id_number).first()

        if not student:
            error = 'Account not found.'
        elif not check_password_hash(student.password, password):
            error = 'Incorrect password.'
        else:
            session.clear()
            session['student_id'] = student.id
            session['student_name'] = student.first_name
            return redirect(url_for('dashboard'))

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None

    if request.method == 'POST':
        id_number = request.form.get('id_number', '').strip()
        last_name = request.form.get('last_name', '').strip()
        first_name = request.form.get('first_name', '').strip()
        middle_name = request.form.get('middle_name', '').strip()
        course = request.form.get('course', '').strip()
        course_level = request.form.get('course_level', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        repeat_password = request.form.get('repeat_password', '').strip()
        address = request.form.get('address', '').strip()

        if not id_number or not last_name or not first_name or not course or not course_level or not email or not password or not repeat_password:
            error = 'Please fill in all required fields.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        elif password != repeat_password:
            error = 'Passwords do not match.'
        elif Student.query.filter_by(id_number=id_number).first():
            error = 'ID number already registered.'
        elif Student.query.filter_by(email=email).first():
            error = 'Email already registered.'
        else:
            hashed_pw = generate_password_hash(password)

            new_student = Student(
                id_number=id_number,
                last_name=last_name,
                first_name=first_name,
                middle_name=middle_name,
                course=course,
                course_level=course_level,
                email=email,
                password=hashed_pw,
                address=address,
                profile_pic='default.png'
            )

            db.session.add(new_student)
            db.session.commit()

            success = 'Registration successful! You can now log in.'

    return render_template('register.html', error=error, success=success)


@app.route('/dashboard')
def dashboard():
    if 'student_id' not in session:
        return redirect(url_for('login'))

    student = Student.query.get(session['student_id'])

    if not student:
        session.clear()
        return redirect(url_for('login'))

    return render_template('dashboard.html', student=student)


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'student_id' not in session:
        return redirect(url_for('login'))

    student = Student.query.get(session['student_id'])

    if not student:
        session.clear()
        return redirect(url_for('login'))

    error = None
    success = None

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        middle_name = request.form.get('middle_name', '').strip()
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        existing = Student.query.filter_by(email=email).first()
        if existing and existing.id != student.id:
            error = 'Email is already used by another account.'
        elif new_password and len(new_password) < 6:
            error = 'New password must be at least 6 characters.'
        elif new_password and new_password != confirm_password:
            error = 'Passwords do not match.'
        else:
            student.first_name = first_name
            student.last_name = last_name
            student.middle_name = middle_name
            student.email = email
            student.address = address

            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and file.filename and allowed_file(file.filename):
                    extension = file.filename.rsplit('.', 1)[1].lower()
                    filename = secure_filename(f"student_{student.id_number}.{extension}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    student.profile_pic = filename

            if new_password:
                student.password = generate_password_hash(new_password)

            db.session.commit()
            session['student_name'] = student.first_name
            success = 'Profile updated successfully!'

    return render_template('edit_profile.html', student=student, error=error, success=success)


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    students = Student.query.order_by(Student.id.desc()).all()
    total_students = Student.query.count()

    return render_template(
        'admin_dashboard.html',
        students=students,
        total_students=total_students
    )


@app.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)