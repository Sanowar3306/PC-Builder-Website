from flask import Flask, request, jsonify, session
from flask_cors import CORS
import bcrypt
import pymongo


uri = "mongodb+srv://project470:project470@projects.pibwcx4.mongodb.net/?retryWrites=true&w=majority&appName=Projects"
client = pymongo.MongoClient(uri)
db = client["PcBuilderWebsite"]
users_collection = db["users"]
products_collection = db["products"]

app = Flask(__name__)
CORS(app)  

app.secret_key = 'your_secret_key_here'

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"message": "Invalid username or password"}), 401
    
    if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"]):
        session['user'] = {"username": user["username"], "email": user["email"], "role": user.get("role", "user")}
        return jsonify({"message": "Login successful", "user": session['user']}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"message": "Invalid admin credentials"}), 401
    
    if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"]) and user.get("role") == "admin":
        session['user'] = {"username": user["username"], "role": user["role"]}
        return jsonify({"message": "Admin login successful", "user": session['user']}), 200
    else:
        return jsonify({"message": "Invalid admin credentials or insufficient privileges"}), 401
        
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    
    if users_collection.find_one({"username": username}):
        return jsonify({"message": "Username already exists"}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user_data = {"username": username, "email": email, "password_hash": hashed_password, "role": "user"}
    users_collection.insert_one(user_data)
    
    return jsonify({"message": "Registration successful"}), 201

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('user', None)
    return jsonify({"message": "Logged out successfully"}), 200

  app.route("/admin", methods=["GET"])
def admin_view():
    return "Admin View Page"

@app.route("/user", methods=["GET"])
def user_view():
    return "User View Page"

if __name__ == "__main__":
    app.run(debug=True)
