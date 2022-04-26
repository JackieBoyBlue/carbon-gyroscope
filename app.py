import requests, logging, json, bcrypt, ast, os
from crypto import make_digest, make_signature
from mongo import add_feedback_to_mongo
from user import User
from data_processing import SelectDataFeed, get_secret
from connect_to_db import run_SQL, fetch_SQL
from sqlalchemy import create_engine, inspect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.session import close_all_sessions
from flask import Flask, request, session, make_response, redirect, render_template, flash, url_for, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_paranoid import Paranoid
from authlib.integrations.requests_client import OAuth2Session
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from uuid import uuid4
from dotenv import load_dotenv
from flask_caching import Cache




# - - - - - - - - - - - - - - - - - - - Configuration - - - - - - - - - - - - - - - - - - - #




# Load environment variables
if os.environ.get('IN_DOCKER'): pass
else: load_dotenv('config/app.env')


# Logging configuration
logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s:%(levelname)s:%(message)s'
)


# Initialise app
app = Flask(__name__)
secret_key = json.loads(get_secret())['SECRET_KEY']
app.secret_key = secret_key
cookie_security = True
app.config['SESSION_COOKIE_SECURE'] = cookie_security
app.config['REMEMBER_COOKIE_SECURE'] = cookie_security
app.config['REMEMBER_COOKIE_HTTPONLY'] = True


# Config cache
if os.environ.get('IN_DOCKER'): cache = Cache(config={'CACHE_TYPE': 'RedisCache', 'CACHE_REDIS_HOST': 'redis'})
else: cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
cache.init_app(app)


# for email server
app.config.from_pyfile('config/email.cfg')
app.config['MAIL_PASSWORD'] = json.loads(get_secret())['MAIL_PASSWORD']
mail = Mail(app)


# Flask Paranoid will protect against a correct cookie coming from the wrong IP address
paranoid = Paranoid(app)
paranoid.redirect_view = '/'


# Configure SQL Alchemy for PostgreSQL & set up databases/tables
database_uri = json.loads(get_secret())['POSTGRES_URI']
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
engine = create_engine(database_uri)
engine.connect()
inspector = inspect(engine)
tables = inspector.get_table_names()
if len(tables) == 0:
    sql_file = open('config/setup_database.sql', 'r')
    sql_cmd = sql_file.read()
    engine.execute(sql_cmd)
    sql_file.close()
# Configure MongoDB
app.config['MONGO_URI'] = json.loads(get_secret())['MONGO_URI']



# Initialise login manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(user_id)
    close_all_sessions()
    return user


# Starling
client_id = 'mEJAF84Iu5UqhmWqm2As'
client_secret = json.loads(get_secret())['CLIENT_SECRET']
auth_url = 'https://oauth-sandbox.starlingbank.com'
starling = 'https://api-sandbox.starlingbank.com'
user_agent = 'CarbonGyroscope / development. Contact us at hello@otato.co.uk'
api_key_id = 'a8ceee5d-3f78-48db-9c5e-060496495576'
rotation_key_id = '9b98ed59-96d5-4ef7-815c-7e33290647e8'



# Our Starling bank account uid for users' payments to us
cg_starling_account = ast.literal_eval(json.loads(get_secret())['BANK_DETAILS'])


# Our processed data outputs a weight in kg. We need to know the amount it will cost us to offset that weight
# this figure will depend on the third party used to purchase offsets:
p_per_kg = 7.2


# Used in confirmation/forgotten password email generation
s = URLSafeTimedSerializer(secret_key)




# - - - - - - - - - - - - - - - - - - - - cG pages - - - - - - - - - - - - - - - - - - - - #




# Index
@app.route('/', methods=['GET', 'POST'])
def index():
    resp = make_response(render_template('index.html', p_per_kg = p_per_kg))
    if 'cookies_notified' not in request.cookies: resp.set_cookie('cookies_notified', 'true')
    return resp



# Sign up / create an account
@app.route('/sign-up', methods=['POST'])
def sign_up():
    exists = fetch_SQL(f"""
        SELECT COUNT(email)
        FROM cg_users
        WHERE email = '{request.form['email']}'
    """)
    if exists[0][0] == 1: flash("An account with that email address already exists")
    else:
        if request.form['password'] == request.form['password_repeat']: 

            email = request.form['email']
            session['email'] = email
            password = request.form['password']
            hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

            user = User(email=email, password_hash=hashed)

            db.session.add(user)
            db.session.commit()

            run_SQL(f"""
                INSERT INTO user_tracking (user_id)
                VALUES ('{user.user_id}')
            """)
            return redirect('/confirm-email')

        else: flash("Passwords don't match")
    return redirect('/')



# Send confirmation email
@app.route('/confirm-email', methods=['GET', 'POST'])
def generate_confirmation_email():
    if request.referrer == url_for('resend_confirmation_email', _external=True): email = request.form.get('email')
    elif request.referrer == url_for('index', _external=True): email =session['email']
    elif request.referrer is None: return abort(401)

    token = s.dumps(email, salt='email-confirm')

    message = Message('Confirm your email address for carbonGyroscope', sender='hello@otato.co.uk', recipients=[email])
    link = url_for('confirm_email', token=token, _external=True)
    message.body = f"Hello,\r\rPlease follow the link below to confirm your email address:\r\r{link}\r\rKind regards,\r\rThe carbonGyroscope team"
    mail.send(message)

    return redirect('/')



# Email confirmation
@app.route('/confirm-email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=7200)
        run_SQL(f"""
            UPDATE cg_users
            SET confirmed_email = 'true'
            WHERE email = '{email}'
        """)
        flash('Thanks for confirming your email address, you can now log in!')
        return redirect('/')
    
    except SignatureExpired:
        flash(f'The link has expired')
        return redirect('/resend-confirmation-email')

    except BadTimeSignature:
        flash("Incorrect link. Please make sure you've entered the entire link and added nothing")
        return redirect('/')



# Resend the confirmation email
@app.route('/resend-confirmation-email')
def resend_confirmation_email():
    return render_template('resend-confirmation-email.html')



# Handle a log in attempt
@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        close_all_sessions()

        if user == None: flash("That email address hasn't been registered yet, please sign up")

        elif user.confirmed_email:
            if not user: flash('Invalid details')

            elif bcrypt.checkpw(password.encode('utf8'), user.password_hash):
                if 'remember_me' in request.form: remember_me = True
                else: remember_me = False
                login_user(user, remember=remember_me)
                return redirect('/starling')
            
            else: flash('Invalid details')

        else: return redirect('/resend-confirmation-email')

    return redirect('/')



# Provide a link where a user can reset their password
@app.route('/forgotten-password')
def forgotten_password():
    return render_template('forgotten-password.html')



# Generate forgotten password email
@app.route('/forgotten-password-email', methods=['POST'])
def generate_forgotten_password_email():
    email = request.form['email']

    token = s.dumps(email, salt='password-reset')

    message = Message('Reset your carbonGyroscope password', sender='hello@otato.co.uk', recipients=[email])
    link = url_for('reset_password', token=token, _external=True)
    message.body = f"Hello,\r\rPlease follow the link below to reset your password:\r\r{link}\r\rKind regards,\r\rThe carbonGyroscope team"
    mail.send(message)

    return redirect('/')



# The page to reset a password
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token=None):

    # The page to enter a new password after following the link
    if request.method == 'GET':
        session['email'] = s.loads(token, salt='password-reset', max_age=86400)

        try:
            return render_template('reset-password.html')
        except SignatureExpired:
            flash('The link has expired')
            return redirect('/')
        except BadTimeSignature:
            flash("Incorrect link. Please make sure you've entered the entire link and added nothing")
            return redirect('/')
    
    # Update the password once 
    elif request.method == 'POST':

        if request.form['password'] == request.form['password_repeat']: 

            password = request.form['password']
            hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

            run_SQL(f"""
                UPDATE cg_users
                SET password_hash = '{hashed.decode()}'
                WHERE email = '{session['email']}'
            """)

            flash("You're password has been updated")

            return redirect('/')
        
        else:
            flash("Your passwords didn't match, please try again")

            return "Your passwords didn't match, please try again"



# Logout
@app.route('/logout')
@login_required
def logout():
    try:
        cookies = request.cookies
        access_token = cookies.get('access_token')
        requests.put(f'{starling}/api/v2/identity/logout', headers={'Authorization': f'Bearer {access_token}', 'user_agent': user_agent})
    except: pass
    logout_user()
    return redirect('/')



# Contact us email
@app.route('/contact-email', methods=['POST', 'GET'])
def contact_email():
    if request.method == 'POST':
        message = Message(f'{request.form["subject"]}', sender='hello@otato.co.uk', recipients=['hello@otato.co.uk'])
        message.body = f'Hello\r{request.form["message"]}\rRegards,\r{request.form["name"]}, {request.form["email"]}'
        mail.send(message)

    return redirect('/#contact')



# Dashboard / user homepage
@app.route('/dashboard')
@login_required
def dashboard():

    # Get some Starling account info
    cookies = request.cookies
    access_token = cookies.get('access_token')
    url = starling + '/api/v2/accounts'
    headers = {'Authorization': f'Bearer {access_token}', 'user_agent': user_agent}
    account_resp = requests.get(url, headers=headers)
    account_dict = json.loads(account_resp.text)

    # Catch an expired access token
    if 'error_description' in account_dict: return redirect('/starling')

    # Get name from Starling
    url = starling + '/api/v2/account-holder/name'
    name_resp = requests.get(url, headers=headers)
    name_dict = json.loads(name_resp.text)
    name  = name_dict['accountHolderName']

    # Get tracking data from DB
    tracking_info = fetch_SQL(f"""
        SELECT *
        FROM user_tracking
        WHERE user_id = '{current_user.user_id}'
    """)

    # Total emitted (kg)
    if tracking_info[0][1] == None: carbon_emitted_kg = 0
    else: carbon_emitted_kg = round(tracking_info[0][1])

    # Carbon balanced (kg)
    if tracking_info[0][2] == None: carbon_balanced_kg = 0
    else: carbon_balanced_kg = round(tracking_info[0][2])

    # Total spent (pennies)
    if tracking_info[0][3] == None: spent_to_date = 0
    else: spent_to_date = tracking_info[0][3]

    # Catch up cost
    catch_up = round((carbon_emitted_kg - carbon_balanced_kg) * p_per_kg)

    # Get webhook on/off
    webhook_check = fetch_SQL(f"""
        SELECT webhook
        FROM cg_users
        WHERE user_id = '{current_user.user_id}'
    """)

    # Get transactions
    txs = fetch_SQL(f"""
        SELECT * FROM tx_dataset
        WHERE user_id = '{current_user.user_id}'
        ORDER BY tx_timestamp DESC
        LIMIT 10;
    """)

    # Response & cookies
    resp = make_response(render_template('dashboard.html', carbon_emitted_kg=round(carbon_emitted_kg), spent_to_date=spent_to_date, carbon_balanced_kg=round(carbon_balanced_kg),
                                         name=name, catch_up=catch_up, txs=txs, webhook_check = webhook_check[0][0]))
    resp.set_cookie(
        'account_uid',
        value=f'{account_dict["accounts"][0]["accountUid"]}',
        secure=cookie_security,
        httponly=True
        )
    resp.set_cookie(
        'default_category',
        value=f'{account_dict["accounts"][0]["defaultCategory"]}',
        secure=cookie_security,
        httponly=True
        )
    if 'cookies_notified' not in cookies: resp.set_cookie('cookies_notified', 'true')
    return resp


@app.route('/about-us')
def about_us():
    return render_template('about-us.html')


@app.route('/add-feedback/<merchant_category>/<tx_id>', methods=['POST'])
def add_feedback(merchant_category, tx_id):
    feedback = ast.literal_eval(request.form.to_dict()[tx_id])
    purchases = []
    for i in feedback:
        purchases.append(list(i.values())[0])
    add_feedback_to_mongo({f'{merchant_category}': purchases})
    return redirect('/dashboard')



# - - - - - - - - - - - - - - - - - - - - Starling pages - - - - - - - - - - - - - - - - - - - - #



# Connect to the Starling API
@app.route('/starling')
@login_required
def connect_to_starling_api():

    # Set up an OAuth session
    client = OAuth2Session(client_id, client_secret)

    # First try fetching a refresh token from the database and using it to get a new access token
    try:
        refresh_token = fetch_SQL(f"""
            SELECT refresh_token
            FROM cg_users
            WHERE user_id = '{current_user.user_id}'
        """)
        token = client.refresh_token(f'{starling}/oauth/access-token', refresh_token=refresh_token[0][0], client_id=client_id, client_secret=client_secret)
        
        # Response and cookies
        resp = make_response(redirect('/dashboard'))
        resp.set_cookie(
            'access_token',
            value=f'{token["access_token"]}',
            secure=cookie_security,
            httponly=True,
            samesite='Strict'
            )

        # Update refresh token in the database
        user = load_user(current_user.user_id)
        user.update_refresh_token(f'{token["refresh_token"]}')

    # Otherwise get an access token
    except:
        uri, state = client.create_authorization_url(auth_url)

        # Response and cookies
        resp = make_response(redirect(uri))
        resp.set_cookie(
            'state',
            value=f'{state}',
            secure=cookie_security,
            httponly=True,
            samesite='Strict'
            )
    
    return resp



# Authorise Starling API connection once returned from their external OAuth login
@app.route('/authorize')
@login_required
def authorize():

    # Session must be reinstated after being redirected to Starling
    cookies = request.cookies
    state = cookies.get('state')
    client = OAuth2Session(client_id, client_secret, state=state)

    # Get the access token. The fetch token method will automatically check the state in case of CSRF attack
    authorization_response = request.url
    token = client.fetch_token(f'{starling}/oauth/access-token', authorization_response=authorization_response, client_id=client_id, client_secret=client_secret)

    # Response and cookies
    resp = make_response(redirect('/dashboard'))
    resp.set_cookie(
        'access_token',
        value=f'{token["access_token"]}',
        secure=cookie_security,
        httponly=True
        )

    # Update refresh token in the database
    user = load_user(current_user.user_id)
    user.update_refresh_token(f'{token["refresh_token"]}')
    
    # If there's no account holder uid on record we'll need to pull one and save it to the DB
    starling_uid_check = fetch_SQL(f"""
        SELECT COUNT(starling_uid)
        FROM cg_users
        WHERE user_id = '{current_user.user_id}'
    """)

    if starling_uid_check[0][0] == 0:
        headers = {'Authorization': f'Bearer {token["access_token"]}', 'user_agent': user_agent}
        url = f'{starling}/api/v2/account-holder'
        r = requests.get(url, headers=headers)
        data = r.json()
        starling_uid = data['accountHolderUid']
        run_SQL(f"""
            UPDATE cg_users
            SET starling_uid = '{starling_uid}'
            WHERE user_id = '{current_user.user_id}'
        """)

    return resp



# Get the catch up amount and redirect to make payment
@app.route('/catch-up/<amount>', methods=['POST'])
@login_required
def catch_up(amount):
    session['amount'] = amount
    return redirect('/make-payment')



# Get the top up amount and redirect to make payment
@app.route('/top-up', methods=['POST'])
@login_required
def top_up():
    session['amount'] = int(float(request.form['amount']) * 100)
    return redirect('/make-payment')



# Issue a payment from the user's account to carbonGyroscope's and update the DB
@app.route('/make-payment')
@login_required
def make_payment():

    # Get the user
    cookies = request.cookies
    access_token = cookies['access_token']
    account_uid = cookies['account_uid']
    category_uid = cookies['default_category']
    amount = int(session['amount'])
    fee = 25

    # 1. Transfer the requested top up amount from the user's Starling account to the carbonGyroscope account
    # Declare variables
    request_target = f'/api/v2/payments/local/account/{account_uid}/category/{category_uid}'
    url = starling + request_target
    date = datetime.now().astimezone()
    date = date.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    date = date[:-2] + ':' + date[-2:] # Colon added to the timezone offset
    body = json.dumps({
        "externalIdentifier": f"{uuid4()}",
        "paymentRecipient": cg_starling_account,
        "reference": "carbonGyroscope", # If this is changed then the catch in the webhook must be changed too!
        "amount": {
            "currency": "GBP",
            "minorUnits": amount
        },
        "spendingCategory": "BILLS_AND_SERVICES"
    }, separators=[",", ":"])

    # Make the digest
    digest = make_digest(body).decode()

    # Make the signature
    signature_headers = f'(request-target): put {request_target}\nDate: {date}\nDigest: {digest}'
    # print(signature_headers)
    signature = make_signature(signature_headers.encode()).decode()
    
    # The authorization value for the header
    authorization = f'Bearer {access_token};Signature keyid="{api_key_id}",algorithm="ecdsa-sha256",headers="(request-target) Date Digest",signature="{signature}"'
    
    # Headers, request & response
    headers = {
        'Date': date,
        'Digest': digest,
        'User-Agent': user_agent,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': authorization
    }
    response = requests.put(url, headers=headers, data=body)

    # 2.a) Confirm payment success
    if response.status_code == 200:    
        # 3.a) Record the purchase so that we can offset it at a later date
        payment_id = json.loads(response.text)['paymentOrderUid']
        session['payment_id'] = payment_id
        
        run_SQL(f"""
            INSERT INTO user_payments(payment_order_uid, user_id, offset_amount_pence, fee_pence)
            VALUES('{payment_id}', '{current_user.user_id}', {amount - fee}, {fee})
        """)

        # 3.b) Update user tracking
        tracking_info = fetch_SQL(f"""
            SELECT spent_to_date, carbon_balanced_kg
            FROM user_tracking
            WHERE user_id = '{current_user.user_id}'
        """)

        # Get the amount for total offset
        if tracking_info[0][0] == None: new_spent = amount
        else: new_spent = tracking_info[0][0] + amount

        # Get an estimate for how much carbon the amount will buy
        kg_offset = (amount - 25) / p_per_kg
        session['kg_offset'] = kg_offset

        if tracking_info[0][1] == None: new_kg = kg_offset
        else: new_kg = tracking_info[0][1] + kg_offset

        # Commit to DB
        run_SQL(f"""
            UPDATE user_tracking
            SET spent_to_date = {new_spent},
                carbon_balanced_kg = {new_kg}
            WHERE user_id = '{current_user.user_id}'
        """)

        return redirect(f'/payment-confirmation/{payment_id}')

    # 2.b) Handle failed payments
    else:
        if 'invalid_token' in response.text:
            return redirect('/starling')
        logging.error(f'{response.text}')
        flash("Unfortunately we were unable to process your payment, please try again later")
        return response.text



# Confirm a payment
@app.route('/payment-confirmation/<payment_id>')
@login_required
def payment_confimation(payment_id):
    if request.referrer == url_for('dashboard', _external=True):
        # Send email confirmation of the payment
        user_email = fetch_SQL(f"""
            SELECT email
            FROM cg_users
            WHERE user_id = '{current_user.user_id}'
        """)

        amount = int(session['amount'])
        kg_offset = round(session['kg_offset'], 3)
        
        email = user_email[0][0]
        body = f"Thank you for your payment of £{amount / 100}.\r\rYour payment reference is {payment_id}."
        message = Message(f'Payment confirmation: {payment_id}', sender='hello@otato.co.uk', recipients=[email])
        message.body = f"Hello,\r\r{body}\r\rKind regards,\r\rThe carbonGyroscope team"
        mail.send(message)

        return render_template('payment-confirmation.html', amount=amount, payment_id=payment_id, kg_offset=kg_offset), {"Refresh": "7; url=/dashboard"}



# Get all usable transactions since the last transaction
@app.route('/get-feed')
@login_required
def get_feed():
    
    # Use this to get all demo transactions
    example = '2020-03-05T00:00:00Z'

    # Get the most recent payment date from the event log
    returned_info = fetch_SQL(f"""
        SELECT event_timestamp
        FROM event_log
        WHERE user_id = '{current_user.user_id}'
        ORDER BY event_timestamp DESC
        LIMIT 1    
    """)
    if len(returned_info) != 0:
        date = str(returned_info[0][0])
        date = date.replace(' ', 'T')
        date = date[:-4]
        date = date + 'Z'
    else: date = str(datetime.today().isoformat() + 'Z')

    # Get the cookies
    cookies = request.cookies
    account_uid = cookies.get('account_uid')
    default_category = cookies.get('default_category')
    access_token = cookies.get('access_token')

    try:
        # Get the transactions
        url = f'{starling}/api/v2/feed/account/{account_uid}/category/{default_category}?changesSince={date}' # changesSince should be {example} when using sandbox transactions or {date} for proper functionality
        headers = {'Authorization': f'Bearer {access_token}', 'user_agent': user_agent}
        feed_resp = requests.get(url, headers=headers)
        feed_dict = json.loads(feed_resp.text)

        # Dump to database
        user = load_user(current_user.user_id)
        usable_data = SelectDataFeed(feed_dict)
        user.dump_to_db(usable_data.tx_data)

        # Add the carbon estimate to the total emitted figure
        co2_kg= usable_data.estimate_carbon()

        tracking_info = fetch_SQL(f"""
            SELECT carbon_emitted_kg
            FROM user_tracking
            WHERE user_id = '{current_user.user_id}'
        """)

        if tracking_info[0][0] == None: new_emitted = co2_kg
        else: new_emitted = tracking_info[0][0] + co2_kg

        run_SQL(f"""
            UPDATE user_tracking
            SET carbon_emitted_kg = {new_emitted}
            WHERE user_id = '{current_user.user_id}'
        """)    

        # Response
        if co2_kg == 0: flash("You haven't made any eligible transactions since your last synchronisation")
        else: flash(f"An estimated {co2_kg}kg CO2e has been emitted by your recent payments")
        resp = make_response(redirect('/dashboard'))

    except:
        logging.error("Could not get transactions")
        flash("Unfortunately an error occured while getting your transaction data, please try again later")
        resp = make_response(redirect('/dashboard'))

    return resp




# - - - - - - - - - - - - - - - - - - - Error handling - - - - - - - - - - - - - - - - - - - - #




@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), {"Refresh": "7; url=/"}


@app.errorhandler(401)
def page_not_found(e):
    return render_template('401.html'), {"Refresh": "7; url=/"}





# - - - - - - - - - - - - - - - - - - - Jinja2 functions - - - - - - - - - - - - - - - - - - - - #



@app.context_processor
def cookies_check():
    consent = request.cookies.get('cookies_notified')
    if consent is None: return {'cookies_check': False}
    else: return {'cookies_check': True}





if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) # ssl_context='adhoc' - fake https for development
 