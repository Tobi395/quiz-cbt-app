from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cbt.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ===================== MODELS =====================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"))
    question = db.Column(db.Text)
    option_a = db.Column(db.String(255))
    option_b = db.Column(db.String(255))
    option_c = db.Column(db.String(255))
    option_d = db.Column(db.String(255))
    correct = db.Column(db.String(1))
    difficulty = db.Column(db.String(20))


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    question_id = db.Column(db.Integer)
    selected = db.Column(db.String(1))


class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    subject_id = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer)
    total = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ===================== LOGIN =====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ===================== ROUTES =====================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        if User.query.filter_by(email=email).first():
            return "Email already exists"

        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect(url_for("index"))
        return "Invalid login"

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ===================== QUIZ =====================

@app.route("/quiz/<int:subject_id>")
@login_required
def take_quiz(subject_id):
    # ❌ prevent retake
    existing = Attempt.query.filter_by(
        user_id=current_user.id,
        subject_id=subject_id
    ).first()

    if existing:
        return redirect(url_for("student_dashboard"))

    subject = Subject.query.get_or_404(subject_id)
    questions = Question.query.filter_by(subject_id=subject.id)\
        .order_by(db.func.random()).limit(40).all()

    session["start_time"] = datetime.utcnow().isoformat()
    session["subject"] = subject.name

    return render_template(
        "take_quiz.html",
        questions=questions,
        subject_id=subject.id
    )



# ===================== AUTOSAVE =====================

@app.route("/autosave", methods=["POST"])
@login_required
def autosave():
    data = request.get_json()

    for qid, ans in data.items():
        record = Answer.query.filter_by(
            user_id=current_user.id,
            question_id=int(qid)
        ).first()

        if record:
            record.selected = ans
        else:
            record = Answer(
                user_id=current_user.id,
                question_id=int(qid),
                selected=ans
            )
            db.session.add(record)

    db.session.commit()
    return jsonify({"status": "saved"})


# ===================== SUBMIT QUIZ =====================

@app.route("/submit/<int:subject_id>", methods=["POST"])
@login_required
def submit(subject_id):
    # ⏱ TIME ENFORCEMENT
    start_time = datetime.fromisoformat(session.get("start_time"))
    if datetime.utcnow() - start_time > timedelta(minutes=50):
        return "Time expired. Quiz auto-submitted."

    answers = Answer.query.filter_by(user_id=current_user.id).all()
    score = 0
    analytics = []

    for a in answers:
        q = Question.query.get(a.question_id)
        if not q:
            continue

        correct = a.selected == q.correct
        if correct:
            score += 1

        analytics.append({
            "question": q.question,
            "selected": a.selected,
            "correct": q.correct,
            "is_correct": correct
        })

    return render_template(
        "result.html",
        score=score,
        total=len(analytics),
        analytics=analytics
    )


# ===================== ADMIN =====================

@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return "Unauthorized"
    return render_template("admin_dashboard.html")


# ===================== RUN =====================

if __name__ == "__main__":
    app.run(debug=True)
