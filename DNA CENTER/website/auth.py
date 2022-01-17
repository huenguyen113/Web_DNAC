from os import name
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import requests
from requests.api import get
import json

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Account does not exist.', category='error')

    return render_template("signin_theme.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Account already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(username) < 2:
            flash('User name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Password don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("signup_theme.html", user=current_user)

def get_token():
    api_path = "https://sandboxdnac.cisco.com/dna"
    auth = ("devnetuser","Cisco123!")
    headers = {"Content-Type":"application/json"}

    auth_resp = requests.post( f"{api_path}/system/api/v1/auth/token", auth = auth, headers = headers, verify=False)

    auth_resp.raise_for_status()
    token = auth_resp.json()["Token"]
    return token

url1 = "https://sandboxdnac.cisco.com/dna/intent/api/v1/device-health"
url2 = "https://sandboxdnac.cisco.com/dna/intent/api/v1/topology/vlan/vlan-names"
url3 = "https://sandboxdnac.cisco.com/dna/intent/api/v1/site"
url4 = "https://sandboxdnac.cisco.com/dna/intent/api/v1/topology/physical-topology"
url5 = "https://sandboxdnac.cisco.com/dna/intent/api/v1/interface"
url6 = "https://sandboxdnac.cisco.com/dna/intent/api/v1/image/importation"

# payload = None
payload = {
    "username":"devnetuser",
    "password":"Cisco123!"
}

token = get_token()

headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Auth-Token": token
}

# response1 = requests.request('GET', url1, headers=headers, data = payload, verify=False)
response2 = requests.request('GET', url2, headers=headers, data = payload, verify=False)
response3 = requests.request('GET', url3, headers=headers, data = payload, verify=False)
response4 = requests.request('GET', url4, headers=headers, data = payload, verify=False)
# response5 = requests.request('GET', url5, headers=headers, data = payload, verify=False)
response6 = requests.request('GET', url6, headers=headers, data = payload, verify=False)

# data1 = response1.json()
data2 = response2.json()
data3 = response3.json()
data4 = response4.json()
# data5 = response5.json()
data6 = response6.json()

# data_json1 = json.dumps(data1, indent=4, sort_keys=True)
data_json2 = json.dumps(data2, indent=4, sort_keys=True)
data_json3 = json.dumps(data3, indent=4, sort_keys=True)
data_json4 = json.dumps(data4, indent=4, sort_keys=True)
# data_json5 = json.dumps(data5, indent=4, sort_keys=True)
data_json6 = json.dumps(data6, indent=4, sort_keys=True)

device = []
resp = requests.get(url1, data = payload, headers = headers, verify = False)
response_json = resp.json()
device = response_json["response"]
name_device = []
overall_health = []
for item in device:
    name_device.append([item["name"]])
for item in device:
    overall_health.append([item["overallHealth"]])

device5 = []
resp5 = requests.get(url5, data = payload, headers = headers, verify = False)
response_json5 = resp5.json()
device5 = response_json5["response"]
name_status = []
up = 0
down = 0
st = []
name_status = [['Up'], ['Down']]
for item in device5:
    status = item["status"]
    if status == 'up':
        up += 1
    elif status == 'down':
        down += 1
st.append([up])
st.append([down])
 
@auth.route('/health')
def health():
   return render_template('health.html', embed = json.dumps(name_device), embed1 = json.dumps(overall_health))

@auth.route('/vlan')
def vlan():
   return render_template('vlan.html', embed2 = data_json2)

@auth.route('/site')
def site():
   return render_template('site.html', embed3 = data_json3)

@auth.route('/topology')
def topology():
   return render_template('topology.html', embed4 = data_json4)

@auth.route('/device')
def device():
   return render_template('device.html', name_sta = json.dumps(name_status), sta = json.dumps(st))
   
@auth.route('/swim')
def swim():
   return render_template('swim.html', embed6 = data_json6)

