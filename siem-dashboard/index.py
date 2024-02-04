from flask import *

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl, smtplib, hashlib, uuid

import psycopg2

import pandas as pd

import datetime, json

app = Flask(__name__)
app.jinja_env.auto_reload = True
app.config["TEMPLATES_AUTO_RELOAD"] = True

DATABASE_URL = "postgresql://postgres:inr_db@db.inr.intellx.in/cybrana"
CONNECTION = psycopg2.connect(DATABASE_URL)

@app.route('/dashboard/SIEM/ongoing')
def dashboard_siem():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM events WHERE NOT RESOLVED;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    data = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    return render_template("SIEM/ongoing.html", data = data)

@app.route('/dashboard/SIEM/all')
def dashboard_siem_all():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM events;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    data = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    return render_template("SIEM/all.html", data=data)

@app.route('/dashboard/SIEM/event/<id>', methods=['GET', 'POST'])
def event_view(id):

    if request.method == "POST":

        cursor = CONNECTION.cursor()

        cursor.execute('''
                INSERT INTO event_comments (
                        event_id,
                        user_id,
                        comment
                    )
                VALUES (
                        %s,
                        1,
                        %s
                    )
            ''', (id, request.form.get("desc")))

        CONNECTION.commit()

        return redirect(url_for('event_view', id=id))

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM events WHERE event_id=%s;', (id,))

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    data = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    event = data[0]

    days_passed = ((event["timestamp"] - datetime.datetime.now()).days) + 1


    cursor.execute('SELECT * FROM incidents WHERE event_id=%s;', (id,))

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    event["incidents"] = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    event["days"] = abs(days_passed)
    event["timestamp"] = event["timestamp"].strftime('%b %d, %Y %I:%M %p')

    event["incidents"] = [{**item, 'timestamp': item['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} for item in event["incidents"]]

    cursor.execute('SELECT * FROM event_comments WHERE event_id=%s;', (id,))

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    event["comments"] = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    return render_template("SIEM/event.html", event = event)

@app.route('/dashboard/SIEM/create', methods=['GET', 'POST'])
def dashboard_siem_create():
    if request.method == "POST":

            cursor = CONNECTION.cursor()

            cursor.execute('''
                INSERT INTO events (
                        event_type,
                        description,
                        source_device,
                        man_interv
                    )
                VALUES (
                        %s,
                        %s,
                        %s,
                        True
                    )
            ''', (request.form.get("type"), request.form.get("desc"), request.form.get("name")))

            CONNECTION.commit()

            return redirect(url_for('dashboard_siem'))

    return render_template("SIEM/create.html")


@app.route('/dashboard/ics', methods=['GET', 'POST'])
def dashboard_ics():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM ics_events;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    logs = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    unique_attacks = list(set(entry['attack'] for entry in logs))

    attack_count_mapping = {attack: sum(entry['relevant_logs'] for entry in logs if entry['attack'] == attack) for attack in unique_attacks}

    return render_template("Maps/att&ck_ics.html", data = attack_count_mapping, keys = attack_count_mapping.keys())

@app.route('/dashboard/ics/all', methods=['GET', 'POST'])
def dashboard_ics_all():

    if request.method=="POST":

        cursor = CONNECTION.cursor()

        cursor.execute('''INSERT INTO trusted_ics_devices (
                                                    id,
                                                    ip,
                                                    type
                                            ) VALUES (%s, %s, %s);''',
                            (request.form.get("id"),request.form.get("ip"),request.form.get("type")))

        CONNECTION.commit()

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM ics_events;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    logs = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    cursor.execute('SELECT * FROM trusted_ics_devices;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    trusted_devices = [{heading: value for heading, value in zip(headings, data)} for data in data_values]\

    unique_attacks = list(set(entry['attack'] for entry in logs))

    attack_count_mapping = {attack: sum(entry['relevant_logs'] for entry in logs if entry['attack'] == attack) for attack in unique_attacks}

    return render_template("ics_all.html", logs=logs, trusted_devices=trusted_devices, pi={"labels":unique_attacks,"numbers":list(attack_count_mapping.values())})

@app.route('/dashboard/ics/del_<id>', methods=['GET', 'POST'])
def dashboard_ics_del(id):

    cursor = CONNECTION.cursor()

    cursor.execute('DELETE FROM trusted_ics_devices WHERE id=%s;', (id,))

    CONNECTION.commit()

    return redirect(url_for("dashboard_ics_all"))

@app.route('/dashboard/resolve/<id>')
def dashboard_siem_resolve(id):

    cursor = CONNECTION.cursor()

    cursor.execute('UPDATE events SET resolved = true, resolution_timestamp = %s WHERE event_id=%s;', (datetime.datetime.now(),id,))

    CONNECTION.commit()

    return redirect(url_for("event_view", id=id))


@app.route('/dashboard/matrix', methods=['GET', 'POST'])
def dashboard_matrix():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM vulns;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    logmap = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    keys = [i["mitre_tactic"] for i in logmap]

    return render_template("Maps/att&ck_updated.html", keys = keys)


@app.route('/dashboard/owasp', methods=['GET', 'POST'])
def dashboard_owasp():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM vulns;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    logmap = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    # Create separate arrays based on "owasp_map"
    A01 = [log for log in logmap if log.get("owasp_map") == "Broken Access Control"]
    A02 = [log for log in logmap if log.get("owasp_map") == "Cryptographic Failures"]
    A03 = [log for log in logmap if log.get("owasp_map") == "Injection"]
    A04 = [log for log in logmap if log.get("owasp_map") == "Insecure Design"]
    A05 = [log for log in logmap if log.get("owasp_map") == "Security Misconfiguration"]
    A06 = [log for log in logmap if log.get("owasp_map") == "Vulnerable and Outdated Components"]
    A07 = [log for log in logmap if log.get("owasp_map") == "Identification and Authentication Failures"]
    A08 = [log for log in logmap if log.get("owasp_map") == "Identification and Authentication Failures"]
    A09 = [log for log in logmap if log.get("owasp_map") == "Security Logging and Monitoring Failuresl"]
    A10 = [log for log in logmap if log.get("owasp_map") == "Server-Side Request Forgery (SSRF)"]


    return render_template("Maps/owasp.html",
                A01 = A01,
                A02 = A02,
                A03 = A03,
                A04 = A04,
                A05 = A05,
                A06 = A06,
                A07 = A07,
                A08 = A08,
                A09 = A09,
                A10 = A10,
                n = len(logmap))

#!-- Get live data from dbase.

@app.route('/dashboard/ldap', methods=['GET', 'POST'])
def dashboard_ldap():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM ldap_rolechanges;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    data = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    return render_template("ldap.html", changes=data)

@app.route('/dashboard/ids', methods=['GET', 'POST'])
def dashboard_ids():

    return render_template("ids.html")


@app.route('/dashboard/events/all')
def dashboard_events_all():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM vulns;')

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    data = [{heading: value for heading, value in zip(headings, data)} for data in data_values]

    return render_template("events_all.html", data=data)


@app.route('/dashboard/tactic')
def dashboard_event_tactic():

    cursor = CONNECTION.cursor()

    cursor.execute('SELECT * FROM vulns WHERE mitre_tactic=%s;', (request.args.get("id"),))

    headings = [desc[0] for desc in cursor.description]
    data_values = list(cursor.fetchall())

    data = [{heading: value for heading, value in zip(headings, data)} for data in data_values]
    return render_template("event_tactic.html", data=data)

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

if __name__ == '__main__':    
    app.run(debug=True)