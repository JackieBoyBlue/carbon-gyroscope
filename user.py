import datetime, logging, os
from sqlalchemy.dialects.postgresql.base import BYTEA
from sqlalchemy.sql.sqltypes import Boolean, String
from sqlalchemy.dialects.postgresql import UUID
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from uuid import uuid4
from connect_to_db import run_SQL




# Initialise app
app = Flask('__name__')
logger = logging.getLogger(__name__)



# Configure SQL Alchemy for PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)



# The user class
class User(db.Model, UserMixin):

    # Configure counterparts in Postgres
    __tablename__ = 'cg_users'
    user_id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    email = db.Column(String(320), unique=True)
    refresh_token = db.Column(String(64), unique=True)
    starling_uid = db.Column(UUID(as_uuid=True))
    password_hash = db.Column(BYTEA, nullable=False)
    confirmed_email = db.Column(Boolean)

    #Initialise user
    def __init__(self, email, password_hash, user_id=None, refresh_token=None, confirmed_email=False):
        self.email = email
        self.password_hash = password_hash
        self.user_id = user_id
        self.refresh_token = refresh_token
        self.confirmed_email = confirmed_email


    # Repr
    def __repr__(self) -> str:
        return f"User ID: {self.user_id}\nRefresh token: {self.refresh_token}\nEmail address: {self.email}\nConfirmed email: {self.confirmed_email}"


    # Get the user's ID
    def get_id(self) -> UUID:
        return self.user_id


    # Add data user transaction data to the database
    def dump_to_db(self, tx_data) -> None:
        logger.info('Dumping transaction data to database...')
        batch_id = uuid4()

        # Add an eventlog
        run_SQL(f"""
            INSERT INTO event_log (event_timestamp, user_id, batch_id, added_to_db, error_count)
            VALUES('{datetime.datetime.today()}', '{self.user_id}', '{batch_id}', '0', '0')
        """)
        logger.info('Batch registered in event log')

        # Add transactions to the database
        error_count = 0
        added_to_db = 0
        for tx in tx_data:
            error_check = run_SQL(f"""
                INSERT INTO tx_dataset (tx_id, batch_id, amount_in_pence, category, company, user_id, tx_timestamp)
                VALUES ('{tx}', '{batch_id}', {tx_data[tx][0]}, '{tx_data[tx][1]}', '{tx_data[tx][2]}', '{self.user_id}', '{tx_data[tx][3]}')
            """)
            if error_check != None: error_count += 1
            elif error_check == None: added_to_db += 1
        
        # .log successes and errors 
        if error_count == 0: logger.info(f'{added_to_db} transactions successfully added to database')
        else: 
            logger.error(f'{error_count}/{error_count + added_to_db} errors occured while dumping to database')
        
        # Update the database eventlog w/ successes and errors
        run_SQL(f"""
            UPDATE event_log
            SET added_to_db = '{added_to_db}',
                error_count = '{error_count}'
            WHERE batch_id = '{batch_id}'
        """)

    # Update refresh token
    def update_refresh_token(self, token) -> None:
        self.refresh_token = token
        run_SQL(f"""
            UPDATE cg_users
            SET refresh_token = '{token}'
            WHERE user_id = '{self.user_id}'
        """)
