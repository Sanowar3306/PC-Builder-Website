from db_create import mongo_db
from basic_fuctionalities import BasicFunctionalities

class db_collections_values:
    def __init__(self, db_values):
        self.db = db_values  # This should be an instance of BasicFunctionalities

    def insert_sample_data(self):
        user_data = {
            "username": "john_doe",
            "email": "john@example.com",
            "password_hash": "hashed_password_123",
            "wishlist": [],
            "alerts": [],
            "orders": []
        }
        self.db.insert_user(user_data)

        product_data = {
            "name": "Intel Core i7-12700K",
            "category": "CPU",
            "specs": {
                "cores": 12,
                "threads": 20,
                "base_clock": "3.6GHz",
                "socket": "LGA1700"
            },
            "price": 379.99,
            "vendor_ids": [],
            "ratings": 4.7
        }
        self.db.insert_product(product_data)

        vendor_data = {
            "name": "TechStore",
            "website": "https://techstore.com",
            "rating": 4.5,
            "product_list": []
        }
        self.db.insert_vendor(vendor_data)

        wishlist_data = {
            "user_id": "user123",
            "products": [],
            "notifications_enabled": True
        }
        self.db.insert_wishlist(wishlist_data)

        order_data = {
            "user_id": "user123",
            "items": [],
            "status": "pending",
            "total_price": 0.0,
            "created_at": "2025-04-15"
        }
        self.db.insert_order(order_data)

        rule_data = {
            "component_a": "CPU",
            "component_b": "Motherboard",
            "rule": "socket == LGA1700"
        }
        self.db.insert_compatibility_rule(rule_data)

        print("Sample data inserted into all collections.")

    def show_all_products(self):
        products = self.db.get_all_products()
        for product in products:
            print(product)

if __name__ == "__main__":
    uri = "mongodb+srv://project470:project470@projects.pibwcx4.mongodb.net/?retryWrites=true&w=majority&appName=Projects"
    
    db_instance = mongo_db(uri, "PcBuilderWebsite")
    db_values = BasicFunctionalities(db_instance)

    collections_values = db_collections_values(db_values)
    collections_values.insert_sample_data()
    collections_values.show_all_products()
