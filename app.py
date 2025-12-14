from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, UserMixin, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ===================== MODELS =====================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(300), nullable=False)
    option_a = db.Column(db.String(200))
    option_b = db.Column(db.String(200))
    option_c = db.Column(db.String(200))
    option_d = db.Column(db.String(200))
    correct = db.Column(db.String(1))
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'))

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    subject_id = db.Column(db.Integer)
    score = db.Column(db.Integer)
    total = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===================== ROUTES =====================

@app.route('/')
def index():
    return render_template('index.html')

# ---------- AUTH ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed = generate_password_hash(request.form['password'])
        user = User(
            username=request.form['username'],
            password=hashed,
            role=request.form['role']
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(
                url_for('admin_dashboard') if user.role == 'admin'
                else url_for('student_dashboard')
            )
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------- DASHBOARDS ----------
@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/student')
@login_required
def student_dashboard():
    subjects = Subject.query.all()
    return render_template('student_dashboard.html', subjects=subjects)

# ---------- SUBJECT MANAGEMENT ----------
@app.route('/add-subject', methods=['POST'])
@login_required
def add_subject():
    name = request.form['name']
    if not Subject.query.filter_by(name=name).first():
        db.session.add(Subject(name=name))
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

# ---------- QUESTION ----------
@app.route('/create-question', methods=['GET', 'POST'])
@login_required
def create_question():
    subjects = Subject.query.all()

    if request.method == 'POST':
        q = Question(
            question=request.form['question'],
            option_a=request.form['a'],
            option_b=request.form['b'],
            option_c=request.form['c'],
            option_d=request.form['d'],
            correct=request.form['correct'],
            subject_id=request.form['subject_id']
        )
        db.session.add(q)
        db.session.commit()

    return render_template('create_question.html', subjects=subjects)

# ---------- QUIZ ----------
@app.route('/take-quiz/<int:subject_id>')
@login_required
def take_quiz(subject_id):
    questions = Question.query.filter_by(subject_id=subject_id).all()
    random.shuffle(questions)
    return render_template(
        'take_quiz.html',
        questions=questions,
        subject_id=subject_id
    )

@app.route('/submit-quiz/<int:subject_id>', methods=['POST'])
@login_required
def submit_quiz(subject_id):
    questions = Question.query.filter_by(subject_id=subject_id).all()
    score = 0

    for q in questions:
        if request.form.get(str(q.id)) == q.correct:
            score += 1

    result = Result(
        user_id=current_user.id,
        subject_id=subject_id,
        score=score,
        total=len(questions)
    )
    db.session.add(result)
    db.session.commit()

    return render_template(
        'result.html',
        score=score,
        total=len(questions)
    )

# ---------- HISTORY ----------
@app.route('/history')
@login_required
def history():
    results = Result.query.filter_by(user_id=current_user.id).all()
    subjects = {s.id: s.name for s in Subject.query.all()}
    return render_template(
        'quiz_history.html',
        results=results,
        subjects=subjects
    )

# ===================== RUN =====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
