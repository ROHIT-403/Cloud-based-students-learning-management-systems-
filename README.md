# Cloud-based-students-learning-management-systems-
learning kms system 
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlite3, os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lms.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
MATERIALS_FOLDER = os.path.join(UPLOAD_FOLDER, "materials")
SUBMISSIONS_FOLDER = os.path.join(UPLOAD_FOLDER, "submissions")
for folder in (UPLOAD_FOLDER, MATERIALS_FOLDER, SUBMISSIONS_FOLDER):
    os.makedirs(folder, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          user_id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','teacher','admin'))
        );
        CREATE TABLE IF NOT EXISTS courses(
          course_id INTEGER PRIMARY KEY AUTOINCREMENT,
          course_name TEXT NOT NULL, description TEXT,
          teacher_id INTEGER, FOREIGN KEY(teacher_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS enrollments(
          student_id INTEGER, course_id INTEGER,
          PRIMARY KEY(student_id, course_id),
          FOREIGN KEY(student_id) REFERENCES users(user_id) ON DELETE CASCADE,
          FOREIGN KEY(course_id) REFERENCES courses(course_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS materials(
          material_id INTEGER PRIMARY KEY AUTOINCREMENT,
          course_id INTEGER NOT NULL, title TEXT NOT NULL, file_path TEXT NOT NULL,
          upload_date TEXT NOT NULL,
          FOREIGN KEY(course_id) REFERENCES courses(course_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS assignments(
          assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
          course_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT,
          deadline TEXT NOT NULL,
          FOREIGN KEY(course_id) REFERENCES courses(course_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS submissions(
          submission_id INTEGER PRIMARY KEY AUTOINCREMENT,
          assignment_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
          file_path TEXT NOT NULL, submission_date TEXT NOT NULL,
          marks REAL, feedback TEXT,
          UNIQUE(assignment_id, student_id),
          FOREIGN KEY(assignment_id) REFERENCES assignments(assignment_id) ON DELETE CASCADE,
          FOREIGN KEY(student_id) REFERENCES users(user_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS announcements(
          announcement_id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL,
          author_id INTEGER, course_id INTEGER,
          FOREIGN KEY(author_id) REFERENCES users(user_id),
          FOREIGN KEY(course_id) REFERENCES courses(course_id) ON DELETE CASCADE
        );
        """)
        # Seed demo accounts only when database is empty.
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            demo = [
                ("Admin", "admin@lms.com", "admin123", "admin"),
                ("Demo Teacher", "teacher@lms.com", "teacher123", "teacher"),
                ("Demo Student", "student@lms.com", "student123", "student")
            ]
            for name,email,password,role in demo:
                db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                           (name,email,generate_password_hash(password),role))
            teacher_id = db.execute("SELECT user_id FROM users WHERE email='teacher@lms.com'").fetchone()[0]
            db.execute("INSERT INTO courses(course_name,description,teacher_id) VALUES(?,?,?)",
                       ("Introduction to Python", "Basics of Python programming.", teacher_id))
            student_id = db.execute("SELECT user_id FROM users WHERE email='student@lms.com'").fetchone()[0]
            course_id = db.execute("SELECT course_id FROM courses LIMIT 1").fetchone()[0]
            db.execute("INSERT INTO enrollments(student_id,course_id) VALUES(?,?)", (student_id,course_id))

def login_required(role=None):
    def decorator(view):
        from functools import wraps
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") not in ([role] if isinstance(role,str) else role):
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not name or not email or len(password) < 6:
            flash("Enter your name, valid email, and a password of at least 6 characters.", "error")
            return render_template("register.html")
        try:
            with get_db() as db:
                db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                           (name,email,generate_password_hash(password),"student"))
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(user_id=user["user_id"], name=user["name"], role=user["role"])
            return redirect(url_for("dashboard"))
        flash("Incorrect email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required()
def dashboard():
    role = session["role"]
    with get_db() as db:
        if role == "student":
            courses = db.execute("""SELECT c.* FROM courses c JOIN enrollments e ON c.course_id=e.course_id
                                    WHERE e.student_id=?""", (session["user_id"],)).fetchall()
            assignments = db.execute("""SELECT a.*,c.course_name,s.submission_id,s.marks,s.feedback
              FROM assignments a JOIN courses c ON a.course_id=c.course_id
              JOIN enrollments e ON e.course_id=c.course_id
              LEFT JOIN submissions s ON s.assignment_id=a.assignment_id AND s.student_id=e.student_id
              WHERE e.student_id=? ORDER BY a.deadline""", (session["user_id"],)).fetchall()
        elif role == "teacher":
            courses = db.execute("SELECT * FROM courses WHERE teacher_id=?", (session["user_id"],)).fetchall()
            assignments = db.execute("""SELECT a.*,c.course_name FROM assignments a JOIN courses c ON a.course_id=c.course_id
                                        WHERE c.teacher_id=? ORDER BY a.deadline""", (session["user_id"],)).fetchall()
        else:
            courses = db.execute("SELECT * FROM courses").fetchall()
            assignments = db.execute("SELECT a.*,c.course_name FROM assignments a JOIN courses c ON a.course_id=c.course_id").fetchall()
        announcements = db.execute("SELECT * FROM announcements ORDER BY created_at DESC LIMIT 8").fetchall()
        counts = { "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                   "courses": db.execute("SELECT COUNT(*) FROM courses").fetchone()[0],
                   "assignments": db.execute("SELECT COUNT(*) FROM assignments").fetchone()[0] }
    return render_template("dashboard.html", courses=courses, assignments=assignments,
                           announcements=announcements, counts=counts)

@app.route("/courses")
@login_required()
def courses():
    with get_db() as db:
        if session["role"] == "student":
            rows = db.execute("""SELECT c.*,u.name teacher_name FROM courses c LEFT JOIN users u ON u.user_id=c.teacher_id
                                 JOIN enrollments e ON e.course_id=c.course_id WHERE e.student_id=?""",
                              (session["user_id"],)).fetchall()
        elif session["role"] == "teacher":
            rows = db.execute("SELECT c.*,u.name teacher_name FROM courses c LEFT JOIN users u ON u.user_id=c.teacher_id WHERE c.teacher_id=?",
                              (session["user_id"],)).fetchall()
        else:
            rows = db.execute("SELECT c.*,u.name teacher_name FROM courses c LEFT JOIN users u ON u.user_id=c.teacher_id").fetchall()
        teachers = db.execute("SELECT user_id,name FROM users WHERE role='teacher'").fetchall()
    return render_template("courses.html", courses=rows, teachers=teachers)

@app.route("/courses/create", methods=["POST"])
@login_required(["admin","teacher"])
def create_course():
    name = request.form.get("course_name","").strip()
    description = request.form.get("description","").strip()
    teacher_id = session["user_id"] if session["role"] == "teacher" else request.form.get("teacher_id")
    if not name:
        flash("Course name is required.", "error")
    else:
        with get_db() as db:
            db.execute("INSERT INTO courses(course_name,description,teacher_id) VALUES(?,?,?)",
                       (name,description,teacher_id or None))
        flash("Course created.", "success")
    return redirect(url_for("courses"))

@app.route("/courses/<int:course_id>/enroll", methods=["POST"])
@login_required("student")
def enroll(course_id):
    try:
        with get_db() as db:
            db.execute("INSERT INTO enrollments(student_id,course_id) VALUES(?,?)",
                       (session["user_id"],course_id))
        flash("You are enrolled in the course.", "success")
    except sqlite3.IntegrityError:
        flash("You are already enrolled, or the course does not exist.", "error")
    return redirect(url_for("courses"))

def course_access(course_id):
    with get_db() as db:
        course = db.execute("SELECT * FROM courses WHERE course_id=?", (course_id,)).fetchone()
        if not course: return False
        if session["role"] == "admin": return True
        if session["role"] == "teacher": return course["teacher_id"] == session["user_id"]
        return db.execute("SELECT 1 FROM enrollments WHERE student_id=? AND course_id=?",
                          (session["user_id"],course_id)).fetchone() is not None

@app.route("/courses/<int:course_id>")
@login_required()
def course_detail(course_id):
    if not course_access(course_id):
        flash("You do not have access to this course.", "error")
        return redirect(url_for("courses"))
    with get_db() as db:
        course = db.execute("SELECT * FROM courses WHERE course_id=?", (course_id,)).fetchone()
        materials = db.execute("SELECT * FROM materials WHERE course_id=? ORDER BY upload_date DESC", (course_id,)).fetchall()
        assignments = db.execute("SELECT * FROM assignments WHERE course_id=? ORDER BY deadline", (course_id,)).fetchall()
        submissions = db.execute("""SELECT s.*,u.name student_name,a.title assignment_title
          FROM submissions s JOIN users u ON u.user_id=s.student_id JOIN assignments a ON a.assignment_id=s.assignment_id
          WHERE a.course_id=? ORDER BY s.submission_date DESC""", (course_id,)).fetchall()
    return render_template("course_detail.html", course=course, materials=materials,
                           assignments=assignments, submissions=submissions)

@app.route("/courses/<int:course_id>/materials/upload", methods=["POST"])
@login_required(["teacher","admin"])
def upload_material(course_id):
    if not course_access(course_id): return redirect(url_for("courses"))
    file = request.files.get("file")
    title = request.form.get("title","").strip()
    if not file or not file.filename or not title:
        flash("Provide a title and select a file.", "error")
        return redirect(url_for("course_detail",course_id=course_id))
    filename = secure_filename(file.filename)
    saved = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    file.save(os.path.join(MATERIALS_FOLDER,saved))
    with get_db() as db:
        db.execute("INSERT INTO materials(course_id,title,file_path,upload_date) VALUES(?,?,?,?)",
                   (course_id,title,saved,datetime.now().isoformat(timespec="minutes")))
    flash("Study material uploaded.", "success")
    return redirect(url_for("course_detail",course_id=course_id))

@app.route("/materials/<path:filename>")
@login_required()
def download_material(filename):
    return send_from_directory(MATERIALS_FOLDER, filename, as_attachment=True)

@app.route("/courses/<int:course_id>/assignments/create", methods=["POST"])
@login_required(["teacher","admin"])
def create_assignment(course_id):
    if not course_access(course_id): return redirect(url_for("courses"))
    title = request.form.get("title","").strip()
    description = request.form.get("description","").strip()
    deadline = request.form.get("deadline","")
    if not title or not deadline:
        flash("Assignment title and deadline are required.", "error")
    else:
        with get_db() as db:
            db.execute("INSERT INTO assignments(course_id,title,description,deadline) VALUES(?,?,?,?)",
                       (course_id,title,description,deadline))
        flash("Assignment created.", "success")
    return redirect(url_for("course_detail",course_id=course_id))

@app.route("/assignments/<int:assignment_id>/submit", methods=["POST"])
@login_required("student")
def submit_assignment(assignment_id):
    with get_db() as db:
        assignment = db.execute("SELECT * FROM assignments WHERE assignment_id=?", (assignment_id,)).fetchone()
    if not assignment or not course_access(assignment["course_id"]):
        flash("Assignment not found or access denied.", "error")
        return redirect(url_for("courses"))
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Select a file to submit.", "error")
        return redirect(url_for("course_detail",course_id=assignment["course_id"]))
    filename = secure_filename(file.filename)
    saved = f"student{session['user_id']}_{assignment_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    file.save(os.path.join(SUBMISSIONS_FOLDER,saved))
    with get_db() as db:
        db.execute("""INSERT INTO submissions(assignment_id,student_id,file_path,submission_date)
          VALUES(?,?,?,?) ON CONFLICT(assignment_id,student_id) DO UPDATE SET
          file_path=excluded.file_path,submission_date=excluded.submission_date""",
          (assignment_id,session["user_id"],saved,datetime.now().isoformat(timespec="minutes")))
    flash("Assignment submitted successfully.", "success")
    return redirect(url_for("course_detail",course_id=assignment["course_id"]))

@app.route("/submissions/<path:filename>")
@login_required(["teacher","admin"])
def download_submission(filename):
    return send_from_directory(SUBMISSIONS_FOLDER,filename,as_attachment=True)

@app.route("/submissions/<int:submission_id>/grade", methods=["POST"])
@login_required(["teacher","admin"])
def grade_submission(submission_id):
    marks = request.form.get("marks","").strip()
    feedback = request.form.get("feedback","").strip()
    try:
        marks_value = float(marks)
        if marks_value < 0 or marks_value > 100: raise ValueError
    except ValueError:
        flash("Marks must be a number between 0 and 100.", "error")
        return redirect(url_for("dashboard"))
    with get_db() as db:
        row = db.execute("""SELECT s.submission_id,c.teacher_id FROM submissions s
          JOIN assignments a ON a.assignment_id=s.assignment_id JOIN courses c ON c.course_id=a.course_id
          WHERE s.submission_id=?""",(submission_id,)).fetchone()
        if not row or (session["role"] == "teacher" and row["teacher_id"] != session["user_id"]):
            flash("Submission not found or access denied.", "error")
            return redirect(url_for("dashboard"))
        db.execute("UPDATE submissions SET marks=?,feedback=? WHERE submission_id=?",
                   (marks_value,feedback,submission_id))
    flash("Marks and feedback saved.", "success")
    return redirect(url_for("dashboard"))

@app.route("/announcements/create", methods=["POST"])
@login_required(["teacher","admin"])
def create_announcement():
    title=request.form.get("title","").strip()
    message=request.form.get("message","").strip()
    if title and message:
        with get_db() as db:
            db.execute("INSERT INTO announcements(title,message,created_at,author_id) VALUES(?,?,?,?)",
                       (title,message,datetime.now().isoformat(timespec="minutes"),session["user_id"]))
        flash("Announcement published.", "success")
    else: flash("Announcement title and message are required.", "error")
    return redirect(url_for("dashboard"))

@app.route("/admin/users")
@login_required("admin")
def admin_users():
    with get_db() as db:
        users=db.execute("SELECT user_id,name,email,role FROM users ORDER BY role,name").fetchall()
    return render_template("admin_users.html",users=users)

@app.route("/admin/users/create", methods=["POST"])
@login_required("admin")
def admin_create_user():
    name=request.form.get("name","").strip()
    email=request.form.get("email","").strip().lower()
    password=request.form.get("password","")
    role=request.form.get("role","student")
    if role not in ("student","teacher","admin") or not name or not email or len(password)<6:
        flash("Check user details. Password must be at least 6 characters.", "error")
    else:
        try:
            with get_db() as db:
                db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                           (name,email,generate_password_hash(password),role))
            flash("User created.", "success")
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot delete your own active admin account.", "error")
    else:
        with get_db() as db:
            db.execute("DELETE FROM users WHERE user_id=?", (user_id,))
        flash("User deleted.", "success")
    return redirect(url_for("admin_users"))

@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum upload size is 20 MB.", "error")
    return redirect(request.referrer or url_for("dashboard"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
