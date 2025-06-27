# auth.py
from flask import session, redirect, url_for, render_template_string, request
from app import app

app.secret_key = "CHANGE_THIS_SECRET_KEY"

login_form = '''
<!DOCTYPE html>
<html><body style="background:#111; color:#fff; padding:2em;">
<h2>Admin Login</h2>
<form method="post">
  Username: <input type="text" name="username" /><br>
  Password: <input type="password" name="password" /><br>
  <button type="submit">Login</button>
</form>
</body></html>
'''

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin123":
            session["user"] = "admin"
            return redirect("/index.html")
        return "Invalid credentials", 401
    return render_template_string(login_form)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.before_request
def require_login():
    if request.path.startswith("/api") or request.path.startswith("/login") or request.path.startswith("/static"):
        return
    if not session.get("user"):
        return redirect("/login")
