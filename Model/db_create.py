import pymongo

class mongo_db:
    def __init__(self, uri, db_name):
        self.client = pymongo.MongoClient(uri)
        self.db = self.client[db_name]

        # Collections
        self.users = self.db["users"]
        self.products = self.db["products"]
        self.vendors = self.db["vendors"]
        self.wishlists = self.db["wishlists"]
        self.orders = self.db["orders"]
        self.compatibility_rules = self.db["compatibility_rules"]

if __name__ == "__main__":
    uri = "mongodb+srv://project470:project470@projects.pibwcx4.mongodb.net/?retryWrites=true&w=majority&appName=Projects"
    db_server = mongo_db(uri, "PcBuilderWebsite")
