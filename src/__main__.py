#import agrparse
from src.db_manager.db_manager import DbManager
from src.hacker.db_update.db_updater import DbUpdater
from src.hacker.db_create.db_creator import DbCreator
from src.hacker.db_delete.db_deleter import DbDeleter
from src.hacker.db_dump.db_dumper import DbDumper
from wakepy import set_keepawake, unset_keepawake
import argparse
import time


def main():

    # User input processing with argparse
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('mode', type=str, help="Action to perform", nargs="?", \
        choices=("create_db", "delete_db", "dump_db", "populate_cache", "update_db"))
    parser.add_argument('db_host', type=str, help="Database IP address") #localhost
    parser.add_argument('db_user', type=str, help="Database username") #root
    parser.add_argument('db_password', type=str, help="Database password") #root
    parser.add_argument('db_name', type=str, help="Database name") #test
    parser.add_argument('--clear_cache', action='store_true', help="Clears the database cache")
    args = parser.parse_args()

    set_keepawake(keep_screen_awake=False)
    start_time = time.time()

    if args.mode == "create_db":
        creator = DbCreator(args.db_host, args.db_user, args.db_password, args.db_name)
        creator.create_db()
    elif args.mode == "delete_db":
        deleter = DbDeleter(args.db_host, args.db_user, args.db_password, args.db_name)
        deleter.delete_db()
    elif args.mode == "dump_db":
        dumper = DbDumper(args.db_host, args.db_user, args.db_password, args.db_name)
        dumper.dump_db()
    elif args.mode == "populate_cache":
        updater = DbUpdater(args.db_host, args.db_user, args.db_password, args.db_name)
        if args.clear_cache is not None:
            updater.populate_cve_cache(True)
        else:
            updater.populate_cve_cache(False)

        resp = input("Cache populated. Do you wish to update the database? [y/n]")
        while (resp != "y" and resp != "n"):
            print(resp)
            resp = input("Please prompt a valid answer. Do you wish to update the database? [y/n]")

        if resp == "y":
            updater.update_db()
    elif args.mode == "update_db":
        updater = DbUpdater(args.db_host, args.db_user, args.db_password, args.db_name)
        updater.update_db()

    print("--- %s minutes ---" % ((time.time() - start_time) / 60))
    unset_keepawake()