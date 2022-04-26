import os, json
from flask_pymongo import PyMongo, MongoClient
from flask import Flask



# Config
app = Flask(__name__)
if os.environ.get('IN_DOCKER'):
    app.config['MONGO_URI'] = "mongodb://root:example@mongo:27017"
    client = MongoClient(host="mongodb://root:example@mongo",
                port=27017,
                username='root',
                password='example',
                authSource="admin")
else:
    app.config['MONGO_URI'] = "mongodb://localhost:27017"
    client = MongoClient("mongodb://localhost:27017")
mongo = PyMongo(app)
db = client['carbonGyroscope']
col = db['rates']



def initialise_mongo():
    cursor = mongo.db
    cursor.rates.insert_one(json.load(open('config/mongodb_rates.json')))




def update_merchant_hit_count(category:str, merchant:str) -> None:
    categories = []
    cursor = mongo.db.rates
    docs = cursor.find()
    for doc in docs:
        categories.append(doc)
    for i in categories:
        if i['category'] == category:
            cursor.update_one(
                {'category': category},
                {'$set': {f'{merchant}.hit_count' : (i[merchant]['hit_count'] + 1)}}
            )
    docs.close()


def add_merchant(category:str, merchant:str) -> None:
    categories = []
    cursor = mongo.db.rates
    docs = cursor.find()
    new_merchant = {merchant: {'rate': 0, 'hit_count': 1}}
    for doc in docs:
        categories.append(doc)
    for i in categories:
        if i['category'] == category:
            cursor.update_one(
                {'category': category},
                {'$set': new_merchant}
            )
    docs.close()


def get_rate(category:str, merchant:str) -> float:
    categories = []
    cursor = mongo.db.rates.find()
    for doc in cursor:
        categories.append(doc)
    cursor.close()
    for i in categories:
        if i['category'] == category:
            if merchant in i:
                update_merchant_hit_count(category, merchant)
                if i[merchant]['rate'] == 0: rate = i['default']
                else: rate = i[merchant]['rate']
                return rate
            else:
                add_merchant(category, merchant)
                return i['default']


def add_feedback_to_mongo(dict) -> None:
    cursor = mongo.db.feedback
    cursor.insert_one(dict)