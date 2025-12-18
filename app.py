import os
import random
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, UserMixin, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import smtplib
from email.message import EmailMessage

# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///quiz.db"
).replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"))
    question = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(200))
    option_b = db.Column(db.String(200))
    option_c = db.Column(db.String(200))
    option_d = db.Column(db.String(200))
    correct = db.Column(db.String(1))

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    subject = db.Column(db.String(100))
    score = db.Column(db.Integer)
    total = db.Column(db.Integer)
    date = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------------------------------
# LOGIN MANAGER
# -------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    msg = EmailMessage()
    msg["Subject"] = "Quiz CBT OTP Verification"
    msg["From"] = os.environ.get("EMAIL_USER")
    msg["To"] = email
    msg.set_content(f"Your OTP is: {otp}")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(os.environ.get("EMAIL_USER"), os.environ.get("EMAIL_PASS"))
        smtp.send_message(msg)

def admin_required(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            return "Access denied"
        return func(*args, **kwargs)
    return wrapper

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        if User.query.filter_by(email=email).first():
            return "User already exists"

        otp = generate_otp()
        user = User(
            email=email,
            password=password,
            otp=otp,
            otp_expiry=datetime.utcnow() + timedelta(minutes=10)
        )

        db.session.add(user)
        db.session.commit()

        send_otp_email(email, otp)
        session["verify_email"] = email
        return redirect(url_for("verify"))

    return render_template("register.html")

# ---------- VERIFY OTP ----------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("verify_email")
    if not email:
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()

    if request.method == "POST":
        if user.otp != request.form["otp"]:
            return "Invalid OTP"

        if datetime.utcnow() > user.otp_expiry:
            return "OTP expired"

        user.is_verified = True
        user.otp = None
        user.otp_expiry = None
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("verify.html")

# ---------- RESEND OTP ----------
@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("verify_email")
    user = User.query.filter_by(email=email).first()

    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()

    send_otp_email(email, otp)
    return redirect(url_for("verify"))

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()

        if not user:
            return "Account not found"

        if not check_password_hash(user.password, request.form["password"]):
            return "Incorrect password"

        if not user.is_verified:
            session["verify_email"] = user.email
            return redirect(url_for("verify"))

        login_user(user)
        return redirect(url_for("student_dashboard"))

    return render_template("login.html")

# ---------- LOGOUT ----------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------- STUDENT DASHBOARD ----------
@app.route("/dashboard")
@login_required
def student_dashboard():
    subjects = Subject.query.all()
    return render_template("student_dashboard.html", subjects=subjects)

# ---------- TAKE QUIZ ----------
@app.route("/quiz/<int:subject_id>")
@login_required
def take_quiz(subject_id):
    questions = Question.query.filter_by(subject_id=subject_id)\
        .order_by(db.func.random()).limit(40).all()

    session["quiz_questions"] = [q.id for q in questions]
    session["start_time"] = datetime.utcnow().isoformat()
    session["subject"] = Subject.query.get(subject_id).name

    return render_template("take_quiz.html", questions=questions, subject_id=subject_id)

# ---------- SUBMIT QUIZ ----------
@app.route("/submit/<int:subject_id>", methods=["POST"])
@login_required
def submit(subject_id):
    start_time = datetime.fromisoformat(session.get("start_time"))
    if datetime.utcnow() - start_time > timedelta(minutes=50):
        return "Time expired"

    question_ids = session.get("quiz_questions", [])
    questions = Question.query.filter(Question.id.in_(question_ids)).all()

    score = 0
    for q in questions:
        if request.form.get(str(q.id)) == q.correct:
            score += 1

    result = Result(
        user_id=current_user.id,
        subject=session.get("subject"),
        score=score,
        total=len(questions)
    )

    db.session.add(result)
    db.session.commit()

    return render_template("result.html", score=score, total=len(questions), result_id=result.id)

# ---------- PDF RESULT ----------
@app.route("/result-pdf/<int:result_id>")
@login_required
def result_pdf(result_id):
    result = Result.query.get_or_404(result_id)
    file_path = f"result_{result.id}.pdf"

    c = canvas.Canvas(file_path, pagesize=A4)
    c.drawString(100, 800, "Quiz CBT Result Slip")
    c.drawString(100, 760, f"Student: {current_user.email}")
    c.drawString(100, 730, f"Subject: {result.subject}")
    c.drawString(100, 700, f"Score: {result.score} / {result.total}")
    c.drawString(100, 670, f"Date: {result.date.strftime('%Y-%m-%d')}")
    c.save()

    return send_file(file_path, as_attachment=True)

# -------------------------------------------------
# ADMIN ROUTES
# -------------------------------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    subjects = Subject.query.all()
    return render_template("admin_dashboard.html", subjects=subjects)

@app.route("/admin/add-subject", methods=["POST"])
@admin_required
def add_subject():
    db.session.add(Subject(name=request.form["name"]))
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/add-question", methods=["POST"])
@admin_required
def add_question():
    q = Question(
        subject_id=request.form["subject_id"],
        question=request.form["question"],
        option_a=request.form["a"],
        option_b=request.form["b"],
        option_c=request.form["c"],
        option_d=request.form["d"],
        correct=request.form["correct"]
    )
    db.session.add(q)
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/results")
@admin_required
def admin_results():
    results = Result.query.order_by(Result.date.desc()).all()
    return render_template("admin_results.html", results=results)

# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
