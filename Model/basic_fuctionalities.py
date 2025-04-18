from db_create import mongo_db

class BasicFunctionalities:
    def __init__(self, db: mongo_db):
        self.db = db

    def insert_user(self, user_data):
        return self.db.users.insert_one(user_data)

    def find_user(self, query):
        return self.db.users.find_one(query)

    def insert_product(self, product_data):
        return self.db.products.insert_one(product_data)

    def get_all_products(self):
        return list(self.db.products.find())

    def insert_vendor(self, vendor_data):
        return self.db.vendors.insert_one(vendor_data)

    def insert_wishlist(self, wishlist_data):
        return self.db.wishlists.insert_one(wishlist_data)

    def insert_order(self, order_data):
        return self.db.orders.insert_one(order_data)

    def insert_compatibility_rule(self, rule_data):
        return self.db.compatibility_rules.insert_one(rule_data)
