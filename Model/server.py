from flask import Flask, request, jsonify, session
from flask_cors import CORS
import bcrypt
import pymongo
from datetime import datetime
from bson import ObjectId
from apscheduler.schedulers.background import BackgroundScheduler
import time
import atexit


uri = "mongodb+srv://project470:project470@projects.pibwcx4.mongodb.net/?retryWrites=true&w=majority&appName=Projects"
client = pymongo.MongoClient(uri)
db = client["PcBuilderWebsite"]
users_collection = db["users"]
products_collection = db["products"]

app = Flask(__name__)
CORS(app)
CORS(app, supports_credentials=True)
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


@app.route("/create-admin", methods=["POST"])
def create_new_admin():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if users_collection.find_one({"username": username}):
        return jsonify({"message": "Username already exists"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_admin = {
        "username": username,
        "email": email,
        "password_hash": hashed_password,
        "role": "admin",
        "permissions": ["manage_users", "manage_products", "manage_vendors"]
    }
    users_collection.insert_one(new_admin)
    return jsonify({"message": "New admin created successfully!"}), 201


@app.route("/api/users", methods=["GET"])
def list_users():
    users = users_collection.find({}, {"password_hash": 0}) 
    return jsonify([{
        "username": u["username"],
        "email": u.get("email", ""),
        "role": u.get("role", "user"),
        "alerts": u.get("alerts", []),
        "wishlist": u.get("wishlist", [])
    } for u in users])



@app.route("/update-user", methods=["PATCH"])
def update_user():
    data = request.get_json()
    username = data.get("username")
    updates = data.get("updates", {})

    if not username:
        return jsonify({"message": "Username is required"}), 400

    if updates:
        result = users_collection.update_one(
            {"username": username},
            {"$set": updates}
        )
        if result.modified_count > 0:
            return jsonify({"message": "User updated successfully"}), 200
        return jsonify({"message": "No changes made"}), 200

    return jsonify({"message": "Nothing to update"}), 400



@app.route("/remove-product-from-wishlist", methods=["POST"])
def remove_product_from_wishlist():
    data = request.get_json()
    user = data.get("user")
    product_name = data.get("product_name")  

    if not user or not product_name:
        return jsonify({"message": "Missing user or product data"}), 400

    
    result = users_collection.update_one(
        {"username": user["username"]},
        {"$pull": {"wishlist": {"name": product_name}}}  
    )

    if result.modified_count > 0:
        return jsonify({"message": f"{product_name} removed from wishlist."}), 200
    else:
        return jsonify({"message": "Product not found in wishlist."}), 404



@app.route("/delete-user", methods=["DELETE", "OPTIONS"])
def delete_user():
    if request.method == "OPTIONS":
        return '', 200

    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"message": "Username required"}), 400

    result = users_collection.delete_one({"username": username})
    if result.deleted_count > 0:
        return jsonify({"message": f"{username} deleted successfully"}), 200
    return jsonify({"message": "User not found"}), 404


@app.route("/ordered-products", methods=["GET"])
def show_ordered_products():
    ordered_items = []
    for user in users_collection.find():
        username = user.get("username", "unknown")
        for order in user.get("orders", []):
            if order.get("status") == "ordered":
                product = order.get("product", {})
                ordered_items.append({
                    "user": username,
                    "name": product.get("name", "Unnamed Product"),
                    "price": product.get("price", 0)
                })
    return jsonify(ordered_items)


@app.route("/all-user-orders", methods=["GET"])
def all_user_orders():
    all_users = users_collection.find({"orders": {"$exists": True, "$ne": []}})
    result = []
    for user in all_users:
        username = user.get("username", "Unknown")
        product_names = [
            order.get("product", {}).get("name", "Unnamed Product")
            for order in user.get("orders", [])
            if order.get("status") == "ordered"
        ]
        if product_names:
            result.append({"username": username, "products": product_names})
    return jsonify(result)

@app.route("/api/products", methods=["GET"])
def get_all_products():
    products = products_collection.find({}, {"_id": 0, "name": 1, "price": 1})
    return jsonify(list(products))


@app.route("/api/products/update-price", methods=["PATCH"])
def update_price():
    data = request.get_json()
    product_id = data.get("productId")
    new_price = data.get("price")
    product_name = data.get("productName")  

    if not product_id or not new_price:
        return jsonify({"message": "Missing product ID or price"}), 400

    
    result = products_collection.update_one(
        {"_id": ObjectId(product_id)},  
        {"$set": {"price": new_price}}
    )

    if result.modified_count > 0:
        return jsonify({"message": f"Price for {product_name} updated successfully"}), 200
    else:
        return jsonify({"message": "Failed to update the product price"}), 500

@app.route("/api/products/reset-price", methods=["PATCH"])
def reset_price():
    data = request.get_json()
    product_id = data.get("productId")
    original_price = data.get("originalPrice")

    if not product_id or not original_price:
        return jsonify({"message": "Missing product ID or original price"}), 400

    
    result = products_collection.update_one(
        {"_id": ObjectId(product_id)},  
        {"$set": {"price": original_price}}
    )

    if result.modified_count > 0:
        return jsonify({"message": "Product price reset successfully"}), 200
    else:
        return jsonify({"message": "Failed to reset the product price"}), 500



@app.route("/api/products/grouped", methods=["GET"])
def get_products_grouped_by_category():
    try:
        
        pipeline = [
            {"$group": {"_id": "$category", "products": {"$push": "$$ROOT"}}}
        ]
        grouped_products = list(products_collection.aggregate(pipeline))

        
        for category in grouped_products:
            category['_id'] = str(category['_id'])  
            for product in category['products']:
                product['_id'] = str(product['_id'])  

        return jsonify(grouped_products), 200
    except Exception as e:
        
        print(f"Error: {e}")  
        return jsonify({"message": "Error fetching products grouped by category"}), 500


@app.route("/check-price-drops", methods=["POST"])
def check_price_drops():
    data = request.get_json()
    user = data.get("user")
    product = data.get("product")

  
    if not user or not product:
        return jsonify({"message": "User or product data is missing"}), 400


    user_doc = users_collection.find_one({"username": user["username"]})
    if not user_doc:
        return jsonify({"message": "User not found"}), 404

    
    if "alerts" not in user_doc:
        users_collection.update_one(
            {"username": user["username"]},
            {"$set": {"alerts": []}}
        )

    
    current_price = product.get("price")
    original_price = product.get("original_price")

    
    if current_price and original_price and current_price < original_price:
        notification = f"Price drop alert: {product['name']} is now cheaper than before!"
        print(f"Sending notification to {user['username']}: {notification}")

        
        result = users_collection.update_one(
            {"username": user["username"]},
            {"$push": {"alerts": notification}}
        )

        print(f"Matched {result.matched_count} document(s), Modified {result.modified_count} document(s).")
        return jsonify({"message": "Notification sent", "notification": notification}), 200

    return jsonify({"message": "No price drop detected"}), 200


@app.route("/user/notifications/<username>", methods=["GET"])
def get_user_notifications(username):
    user = users_collection.find_one({"username": username})
    if user and "alerts" in user:
        return jsonify({"notifications": user["alerts"]})
    return jsonify({"notifications": []})


def scheduled_job():
    print("Running price drop check...")
    with app.app_context():
        client = app.test_client()
        client.post("/check-price-drops")


scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_job, 'interval', hours=1)
scheduler.start()


atexit.register(lambda: scheduler.shutdown())


if __name__ == "__main__":
    app.run(debug=True)
