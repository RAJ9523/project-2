from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bcrypt import hashpw, gensalt, checkpw
import datetime
from flask_cors import CORS
from bson import ObjectId 
# Initialize Flask app and setup MongoDB connection
app = Flask(__name__)
CORS(app)
# Secret key for JWT (use a secure and random key in production)
app.config['JWT_SECRET_KEY'] = '123'  # Change this in production
jwt = JWTManager(app)

@app.route("/",methods=["get"])
def main():
    return "working"
# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/investment_db"
mongo = PyMongo(app)

# User Registration Route
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid input, email and password are required'}), 400

    email = data['email'].strip().lower()  # Ensure no spaces and case-insensitive match
    password = data['password']

    # Check if email already exists in the database
    users_collection = mongo.db.users
    existing_user = users_collection.find_one({"email": email})

    if existing_user:
        return jsonify({'error': 'Email already exists'}), 400

   
    hashed_password = hashpw(password.encode('utf-8'), gensalt())
    
    # Store the new user in the database
    users_collection.insert_one({'email': email, 'password': hashed_password})

    return jsonify({'message': 'User registered successfully!'}), 201


# User Login Route - Generates JWT token
from flask import request, jsonify
from flask_jwt_extended import create_access_token
from bcrypt import checkpw
import datetime

@app.route("/login", methods=["POST"])
def login():
    print("Login route accessed")  # Debugging log to confirm route access
    data = request.get_json()

    if not data or 'email' not in data or 'password' not in data:
        print("Invalid input")  # Debugging log for invalid data
        return jsonify({'error': 'Invalid input, email and password are required'}), 400

    email = data['email'].strip().lower()  # Trim spaces and convert to lowercase
    password = data['password']
    
    # Find user by email in the MongoDB collection
    users_collection = mongo.db.users
    existing_user = users_collection.find_one({"email":email})
    print(existing_user)
    print(f"Existing user: {existing_user}")  # Debug: Check if user is found

    if existing_user:
        print("User exists")
        
        # Compare the hashed password with the one provided by the user
       
        access_token = create_access_token(identity=email, expires_delta=datetime.timedelta(hours=1))
        print(f"Generated access token: {access_token}")  # Debug: Check token generation
        return jsonify({'message': 'Login successful!', 'access_token': access_token,'userid':str(existing_user['_id'])}), 200
        
    else:
        print("User not found")  # Debug: User not found in DB
        return jsonify({'error': 'Invalid credentials'}), 401


from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import datetime

@app.route("/investment", methods=["POST"])
@jwt_required()
def add_investment():
    data = request.get_json()

    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()

    # Check required fields
    if not data.get('type') or not data.get('name') or not data.get('amount') or not data.get('returnRate'):
        return jsonify({"error": "Missing required fields"}), 400

    # Prepare the investment document
    investment = {
        "userId": current_user_id,  # Use the user_id from the JWT token
        "type": data['type'],  # stock, mutual fund, fixed deposit
        "name": data['name'],
        "amount": data['amount'],
        "returnRate": data['returnRate'],
        "prediction": data['amount'] * (data['returnRate'] / 100),  # Prediction based on return rate
        "date": datetime.datetime.utcnow()  # Current date and time
    }

    # Insert investment into the investments collection
    investments_collection = mongo.db.investments
    investments_collection.insert_one(investment)

    return jsonify({"message": "Investment added successfully!", "investment": investment}), 201

# Route to retrieve all investments for the logged-in user
@app.route("/investments", methods=["GET"])
@jwt_required()
def get_investments():
    current_user_id = get_jwt_identity()

    # Retrieve investments for the current user
    investments_collection = mongo.db.investments
    investments = investments_collection.find({"userId": current_user_id})

    investment_list = []
    for investment in investments:
        investment_list.append({
            "type": investment['type'],
            "name": investment['name'],
            "amount": investment['amount'],
            "returnRate": investment['returnRate'],
            "prediction": investment['prediction'],
            "date": investment['date']
        })

    return jsonify({"investments": investment_list}), 200

@app.route('/investment/<investment_id>', methods=['DELETE'])
@jwt_required()
def delete_investment(investment_id):
    # Get user_id from JWT token
    current_user_id = get_jwt_identity()
    print(investment_id)
    # Check if the investment exists and belongs to the current user
    investment = mongo.db.investments.find_one({"_id": ObjectId(investment_id)})

    if not investment:
        return jsonify({"error": "Investment not found"}), 404

    if investment["userId"] != current_user_id:
        return jsonify({"error": "You can only delete your own investments"}), 403

    # Proceed to delete the investment
    mongo.db.investments.delete_one({"_id": ObjectId(investment_id)})

    return jsonify({"message": "Investment deleted successfully"}), 200


if __name__ == "__main__":
    app.run(debug=True)
