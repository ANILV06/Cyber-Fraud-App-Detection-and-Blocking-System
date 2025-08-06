from flask import Flask, render_template, request, redirect, url_for, session, flash
from utils import is_blocked, log_detection, extract_domain
from predictor import predict_url
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime
import socket
from urllib.parse import urlparse
import csv
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Files
LOG_FILE = "logs.csv"
BLOCKED_DOMAINS_FILE = "blocked_domains.txt"
EMAIL_LOG_FILE = "logs/email_requests.csv"

# ============ Utils ============

def read_logs(filename='logs/logs.csv'):
    logs = []
    if os.path.exists(filename):
        with open(filename, newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader, None)  # Skip header
            logs = list(reader)
    return logs

def write_log(url, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, url, result])

def filter_logs(logs, filter_type):
    if filter_type == "safe":
        return [log for log in logs if "✅" in log[2]]
    elif filter_type == "fraud":
        return [log for log in logs if "🚨" in log[2]]
    return logs

def is_domain_live(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False
# ============ Routes ============

from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
from utils import extract_domain, is_blocked, log_detection
from predictor import predict_url

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form["url"].strip()
        domain = extract_domain(url)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Store default response
        result = ""
        is_fraud = False
        show_email_form = False
        notification = None
        already_blocked = None

        if is_blocked(url):
            result = "🚫 Already Blocked"
            message = f"{result}: {domain}"
            already_blocked = "This domain is already in the blocklist."
        else:
            result = predict_url(url)
            message = result

            if "🚨" in result:
                is_fraud = True
                show_email_form = True
                notification = "Request sent to admin to block this URL."

        # ✅ Log the result (whether blocked or not)
        log_detection(domain, result)

        # 👉 Store results in session before redirect
        session['message'] = message
        session['notification'] = notification
        session['already_blocked'] = already_blocked
        session['is_fraud'] = is_fraud
        session['show_email_form'] = show_email_form
        session['url_to_report'] = url

        # 🔁 Redirect to GET route to avoid form resubmission
        return redirect(url_for('home'))

    # Handle GET (after redirect)
    message = session.pop('message', None)
    notification = session.pop('notification', None)
    already_blocked = session.pop('already_blocked', None)
    is_fraud = session.pop('is_fraud', False)
    show_email_form = session.pop('show_email_form', False)
    url_to_report = session.pop('url_to_report', "")

    return render_template(
        "index.html",
        message=message,
        notification=notification,
        already_blocked=already_blocked,
        is_fraud=is_fraud,
        show_email_form=show_email_form,
        url_to_report=url_to_report
    )

@app.route("/dashboard")
def dashboard():
    filter_type = request.args.get("filter", "").lower()
    logs = read_logs()

    seen_urls = set()          # To avoid duplicate URLs
    filtered_logs = []

    for row in logs[::-1]:     # Reverse to show latest first
        url = row[1].strip().lower()
        result = row[2].strip().lower()

        # Deduplicate by URL
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Determine status
        if "blocked" in result:
            status = "blocked"
        elif "fraud" in result:
            status = "fraud"
        elif "safe" in result:
            status = "safe"
        else:
            status = "unknown"

        # Apply filter
        if not filter_type or filter_type == status:
            filtered_logs.append(row)

    # Recalculate counts based on filtered logs
    safe_count = sum(1 for row in filtered_logs if "safe" in row[2].lower())
    fraud_count = sum(1 for row in filtered_logs if "fraud" in row[2].lower())
    blocked_count = sum(1 for row in filtered_logs if "blocked" in row[2].lower())

    return render_template(
        "dashboard.html",
        logs=filtered_logs,
        safe_count=safe_count,
        fraud_count=fraud_count,
        blocked_count=blocked_count,
        filter_type=filter_type
    )


@app.route("/email_confirm", methods=["GET", "POST"])
def email_confirm():
    url = request.args.get("url")
    if request.method == "POST":
        user_name = request.form.get("user_name")
        user_email = request.form.get("user_email")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        os.makedirs("logs", exist_ok=True)
        if not os.path.exists(EMAIL_LOG_FILE):
            with open(EMAIL_LOG_FILE, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "URL", "User Name", "User Email"])

        with open(EMAIL_LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, url, user_name, user_email])

        flash(" Your request has been sent to the admin.", "success")
        return redirect(url_for("home"))

    return render_template("email_confirm.html", url=url)

# ============ Admin Auth ============

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("admin_login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ============ Admin Dashboard ============
@app.route("/admin-dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    logs = read_logs()
    filter_type = request.args.get("filter", "all").lower()

    # Read blocked domains
    try:
        with open(BLOCKED_DOMAINS_FILE, "r") as f:
            blocked_domains = f.read().splitlines()
    except FileNotFoundError:
        blocked_domains = []

    # Count stats
    safe_count = sum(1 for row in logs if "✅" in row[2] or "Safe" in row[2])
    fraud_count = sum(1 for row in logs if "🚨" in row[2] or "Fraud" in row[2])
    total_count = len(logs)

    stats = {
        "total": total_count,
        "safe": safe_count,
        "fraud": fraud_count,
        "live": len(blocked_domains),  # You can split live/blocked if needed
        "blocked": len(blocked_domains)
    }

    # Filter logic
    if filter_type == "safe":
        logs = [log for log in logs if "✅" in log[2] or "Safe" in log[2]]
    elif filter_type == "fraud":
        logs = [log for log in logs if "🚨" in log[2] or "Fraud" in log[2]]
    elif filter_type == "blocked":
        logs = [log for log in logs if log[1] in blocked_domains]
    elif filter_type == "live":
        logs = [log for log in logs if log[1] not in blocked_domains]
    elif filter_type == "total":
        pass  # show all logs

    return render_template(
        "admin_dashboard.html",
        logs=logs[::-1],  # Show latest first
        stats=stats,
        blocked_domains=blocked_domains,
        active_filter=filter_type  # Optional: used for highlighting current card
    )

@app.route("/admin/block", methods=["POST"])
def admin_block():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    domain = request.form.get("domain", "").strip().lower()
    if domain:
        try:
            with open(BLOCKED_DOMAINS_FILE, "r") as f:
                blocked = f.read().splitlines()
        except FileNotFoundError:
            blocked = []

        if domain not in blocked:
            with open(BLOCKED_DOMAINS_FILE, "a") as f:
                f.write(domain + "\n")
            flash(f"{domain} has been manually blocked.", "danger")
        else:
            flash(f"{domain} is already blocked.", "warning")

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/unblock", methods=["POST"])
def admin_unblock():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    domain = request.form.get("domain", "").strip().lower()
    try:
        with open(BLOCKED_DOMAINS_FILE, "r") as f:
            blocked = f.read().splitlines()
        blocked = [d for d in blocked if d != domain]

        with open(BLOCKED_DOMAINS_FILE, "w") as f:
            f.write("\n".join(blocked) + "\n")
        flash(f"{domain} has been unblocked.", "success")
    except FileNotFoundError:
        flash("No blocked domains to unblock.", "warning")

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/email-requests")
def view_email_requests():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    requests_data = []
    if os.path.exists(EMAIL_LOG_FILE):
        with open(EMAIL_LOG_FILE, newline="") as file:
            reader = csv.reader(file)
            requests_data = list(reader)
    return render_template("email_requests.html", requests=requests_data)

from flask import request, redirect, url_for, flash
from datetime import datetime
import csv
import os

@app.route("/submit-email-request", methods=["POST"])
def submit_email_request():
    try:
        name = request.form.get("user_name", "").strip()
        email = request.form.get("user_email", "").strip()
        url = request.form.get("url", "").strip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Skip if any required field is missing
        if not name or not email or not url:
            flash("⚠️ Missing information in the form submission.", "danger")
            return redirect(url_for("home"))

        csv_path = "logs/email_requests.csv"
        file_exists = os.path.isfile(csv_path)

        # Ensure CSV exists with header
        with open(csv_path, "a", newline="") as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["Timestamp", "URL", "User Name", "User Email"])
            writer.writerow([timestamp, url, name, email])

        flash("Your request has been sent to the admin.", "success")

    except Exception as e:
        flash(f"❌ Error submitting request: {str(e)}", "danger")

    return redirect(url_for("home"))


@app.route("/admin/analytics")
def admin_analytics():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    logs = read_logs()
    daily_counts = {}

    total_safe = total_fraud = total_blocked = 0

    for row in logs:
        date_str = row[0].split()[0]
        result = row[2].lower()

        if date_str not in daily_counts:
            daily_counts[date_str] = {"safe": 0, "fraud": 0, "blocked": 0}

        if "blocked" in result:
            daily_counts[date_str]["blocked"] += 1
            total_blocked += 1
        elif "fraud" in result:
            daily_counts[date_str]["fraud"] += 1
            total_fraud += 1
        elif "safe" in result:
            daily_counts[date_str]["safe"] += 1
            total_safe += 1

    sorted_dates = sorted(daily_counts.keys())
    safe_data = [daily_counts[d]["safe"] for d in sorted_dates]
    fraud_data = [daily_counts[d]["fraud"] for d in sorted_dates]
    blocked_data = [daily_counts[d]["blocked"] for d in sorted_dates]

    return render_template(
        "admin_analytics.html",
        dates=sorted_dates,
        safe_data=safe_data,
        fraud_data=fraud_data,
        blocked_data=blocked_data,
        total_safe=total_safe,
        total_fraud=total_fraud,
        total_blocked=total_blocked
    )

from urllib.parse import urlparse

@app.route("/admin/logs/<filter_type>")
def view_filtered_logs(filter_type):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    logs = read_logs()
    try:
        with open(BLOCKED_DOMAINS_FILE, "r", encoding="utf-8") as f:
            blocked_domains = set(f.read().splitlines())
    except FileNotFoundError:
        blocked_domains = set()

    SAFE_EXTENSIONS = (".com", ".org", ".net", ".edu", ".gov", ".in", ".ac.in")

    def get_extension(url):
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        for ext in SAFE_EXTENSIONS:
            if domain.endswith(ext):
                return ext
        return ""

    seen_urls = set()
    filtered_logs = []

    for row in logs:
        url = row[1]
        if url in seen_urls:
            continue  # Skip repeated URL
        seen_urls.add(url)

        result = row[2].lower()
        ext = get_extension(url.lower())
        is_blocked = url in blocked_domains
        is_safe = result.startswith("✅ safe")
        is_fraud = result.startswith("🚨 fraud")
        is_dead = "dead" in result

        if filter_type == "safe":
            if is_safe and not is_dead and not is_blocked:
                filtered_logs.append(row)

        elif filter_type == "fraud":
            if (is_fraud or (is_dead and ext in SAFE_EXTENSIONS)) and not is_blocked:
                filtered_logs.append(row)

        elif filter_type == "blocked":
            if is_blocked:
                row[2] = "⛔ Blocked"  # Force result to blocked
                filtered_logs.append(row)

        elif filter_type == "total":
            if url not in seen_urls:
                filtered_logs.append(row)

    return render_template("filtered_logs.html", logs=filtered_logs, filter_type=filter_type.capitalize())

# ============ Start App ============
if __name__ == "__main__":
    app.run(debug=True)
