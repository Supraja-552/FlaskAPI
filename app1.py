'''from flask import Flask,render_template,url_for,request,redirect,jsonify

from flask_jwt_extended import JWTManager,create_access_token,get_jwt_identity,jwt_required
#from werkzeug.utils import secure_filename
from flask_restful import Resource,Api
from flask_sqlalchemy import SQLAlchemy
import logging
app=Flask(__name__)
app.config['SECRET_KET']='SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
db=SQLAlchemy(app)
api=Api(app)
jwt=JWTManager(app)
with app.app_context():
    db.create_all()
logging.basicConfig(level=logging.DEBUG)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
class UserRegistration(Resource):
    def post(self):
        logging.debug("UserRegistration POST method called")
        data=request.get_json()
        username=data['username']
        password=data['password']
        if not username or not password:
            return {'message':'Missing username or password'},400
        if User.query.filter_by(username=username).first():
            return {'message':'Username already taken'},400
        new_user=User(username=username,password=password)
        db.session.add(new_user)
        db.session.commit()
        return {'message':'user created successfully'}
class UserLogin(Resource):
    def post(self):
        data=request.get_json()
        username=data['username']
        password=data['password']
        user=User.query.filter_by(username=username).first()
        if user and user.password==password :
            access_token=create_access_token(identity=user.id)
            return {'message':access_token},200
        return {'message':'Invalid username or password'},401
api.add_resource(UserRegistration,'/register') 
api.add_resource(UserLogin,'/login')       
if __name__=='__main__':   
    app.run(debug=True)
    
from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app1 = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app1.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app1)


# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app1.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app1.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app1.run()
'''
from flask import Flask,jsonify
app=Flask(__name__)
data=[{'id':"1",
      'username':'root',
      'password':'root'
      },
      {'id':"2",
      'username':'test',
      'password':'test'
      },
      ]
@app.route('/')
def index():
    return "welcome"
@app.route("/data",methods=['GET'])
def get():
    return jsonify({'data':data})
if __name__=='__main__':
    app.run(debug=True)