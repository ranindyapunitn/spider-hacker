from db_manager.db_manager import DbManager

class DbDumper:

    def __init__(self, hostname, user, password, schema_name):
        self.hostname = hostname
        self.user = user
        self.password = password
        self.schema_name = schema_name

    def dump_db(self, output_file):
        manager = DbManager(self.hostname, self.user, self.password, self.schema_name)
        manager.get_data_to_dump()