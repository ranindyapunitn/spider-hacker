from db_manager.db_manager import DbManager

class DbCreator:

    def __init__(self, hostname, user, password, schema_name):
        self.hostname = hostname
        self.user = user
        self.password = password
        self.schema_name = schema_name

    def create_db(self):
        manager = DbManager(self.hostname, self.user, self.password, self.schema_name)
        manager.create_new_db()