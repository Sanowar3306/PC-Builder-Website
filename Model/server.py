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

@app.route("/api/components/<component>", methods=["GET"])
def get_component_products(component):
    products_cursor = products_collection.find({"category": {'$regex': f'^{component}$', '$options': 'i'}})
    
    products = []
    for prod in products_cursor:
        product_info = {
            "name": prod.get('name'),
            "price": prod.get('price'),
            "ratings": prod.get('ratings'),
            "specs": prod.get('specs')
        }
        products.append(product_info)

    return jsonify(products)

  app.route("/admin", methods=["GET"])
def admin_view():
    return "Admin View Page"

@app.route("/user", methods=["GET"])
def user_view():
    return "User View Page"


@app.route("/cart", methods=["POST"])
def add_to_cart():
    data = request.get_json()
    user = data.get("user")
    product = data.get("product")
    if not user or not product:
        return jsonify({"message": "Missing user or product data"}), 400
    users_collection.update_one(
        {"username": user["username"]},
        {"$push": {"orders": {"product": product, "status": "in_cart"}}}
    )
    return jsonify({"message": "Product added to cart"}), 200



@app.route("/wishlist", methods=["POST"])
def add_to_wishlist():
    data = request.get_json()
    user = data.get("user")
    product = data.get("product")

    if not user or not product:
        return jsonify({"message": "Missing user or product data"}), 400
    wishlist = user.get('wishlist', [])
    if any(item['name'] == product['name'] for item in wishlist):
        return jsonify({"message": "This product is already in your wishlist."}), 400
    users_collection.update_one(
        {"username": user["username"]},
        {"$push": {"wishlist": product}}  
    )
    updated_user = users_collection.find_one({"username": user["username"]})
    return jsonify({"message": "Product added to wishlist", "wishlist": updated_user.get("wishlist", [])}), 200



@app.route("/clear-wishlist", methods=["POST"])
def clear_wishlist():
    data = request.get_json()
    user = data.get("user")
    if not user:
        return jsonify({"message": "Missing user data"}), 400
    result = users_collection.update_one(
        {"username": user["username"]},
        {"$set": {"wishlist": []}}  
    )
    if result.modified_count > 0:
        return jsonify({"message": "Wishlist cleared successfully."}), 200
    else:
        return jsonify({"message": "Error clearing wishlist."}), 500



@app.route("/cart/clear", methods=["POST"])
def clear_cart():
    data = request.get_json()
    user = data.get("user")
    if not user:
        return jsonify({"message": "Missing user data"}), 400
    users_collection.update_one(
        {"username": user["username"]},
        {
            "$pull": {
                "orders": {"status": "in_cart"}
            }
        }
    )
    return jsonify({"message": "Cart cleared"}), 200


@app.route("/checkout", methods=["POST"])
def checkout():
    data = request.get_json()
    user = data.get("user")
    username = user.get("username")
    if not username:
        return jsonify({"message": "Missing user data"}), 400

    user_doc = users_collection.find_one({"username": username})
    if not user_doc or "orders" not in user_doc:
        return jsonify({"message": "No orders to checkout"}), 404

    updated_orders = []
    total_price = 0.0

    for i in range(len(user_doc["orders"])):
        order = user_doc["orders"][i]
        if order.get("status") == "in_cart":
            try:
                price = float(order["product"].get("price", 0))
            except (ValueError, TypeError, KeyError):
                price = 0.0
            total_price += price
            user_doc["orders"][i]["status"] = "ordered"
            updated_order = {
                "product": order["product"],
                "status": "ordered"
            }
            updated_orders.append(updated_order)

    if not updated_orders:
        return jsonify({"message": "No items to checkout."}), 400

    db["orders"].insert_one({
        "user_id": username,
        "items": updated_orders,
        "status": "pending",
        "total_price": round(total_price, 2),
        "created_at": datetime.now().strftime("%Y-%m-%d")
    })

    users_collection.update_one(
        {"username": username},
        {"$set": {"orders": user_doc["orders"]}}
    )
    return jsonify({
        "message": "Checkout successful.",
        "items_checked_out": len(updated_orders),
        "total_price": total_price
    }), 200


@app.route("/user/cart/<username>", methods=["GET"])
def get_user_cart(username):
    user = users_collection.find_one({"username": username})
    if user and 'orders' in user:
        cart_items = [o['product'] for o in user['orders'] if o.get('status') == 'in_cart']
        return jsonify(cart_items)
    return jsonify([])


@app.route("/user/wishlist/<username>", methods=["GET"])
def get_user_wishlist(username):
    user = users_collection.find_one({"username": username})
    if user and 'wishlist' in user:
        return jsonify(user['wishlist'])
    return jsonify([])


@app.route("/user/orders/<username>", methods=["GET"])
def get_user_orders(username):
    orders = db["orders"].find({"user_id": username})
    return jsonify([{
        "created_at": order.get("created_at"),
        "status": order.get("status"),
        "total_price": order.get("total_price"),
        "items": order.get("items")
    } for order in orders])


if __name__ == "__main__":
    app.run(debug=True)
