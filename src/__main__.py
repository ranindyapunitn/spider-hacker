#import agrparse
from db_manager.db_manager import DbManager
from hacker.db_update.db_updater import DbUpdater
from hacker.db_create.db_creator import DbCreator
from hacker.db_delete.db_deleter import DbDeleter
from hacker.db_dump.db_dumper import DbDumper
from wakepy import set_keepawake, unset_keepawake
import argparse
import time
import sys


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
    parser.add_argument('--set_awake', action='store_true', help="Forces the host to not go on standby")
    args = parser.parse_args()

    if args.set_awake is not None:
        set_keepawake(keep_screen_awake=False)

    if args.mode == "create_db":
        resp = input("Creating a new database will erase all previously stored data. Are you sure to proceed? [y/n] ")
        while (resp != "y" and resp != "n"):
            print(resp)
            resp = input("Please prompt a valid answer. Are you sure to proceed? [y/n] ")

        if resp == "y":
            print("Creating database...")
            creator = DbCreator(args.db_host, args.db_user, args.db_password, args.db_name)
            creator.create_db()
            print("Database successfully created")
        else:
            sys.exit()
    elif args.mode == "delete_db":
        resp = input("Are you sure you want to delete the exsisting database? [y/n] ")
        while (resp != "y" and resp != "n"):
            print(resp)
            resp = input("Please prompt a valid answer. Are you sure you want to delete the exsisting database? [y/n] ")

        if resp == "y":
            print("Deleting database...")
            deleter = DbDeleter(args.db_host, args.db_user, args.db_password, args.db_name)
            deleter.delete_db()
            print("Database successfully deleted")
        else:
            sys.exit()
    elif args.mode == "dump_db":
        dumper = DbDumper(args.db_host, args.db_user, args.db_password, args.db_name)
        dumper.dump_db()
    elif args.mode == "populate_cache":
        print("Populating cache...")
        updater = DbUpdater(args.db_host, args.db_user, args.db_password, args.db_name)
        if args.clear_cache is not None:
            updater.populate_cve_cache(True)
        else:
            updater.populate_cve_cache(False)

        resp = input("Cache populated. Do you wish to update the database? [y/n] ")
        while (resp != "y" and resp != "n"):
            print(resp)
            resp = input("Please prompt a valid answer. Do you wish to update the database? [y/n] ")

        if resp == "y":
            updater.update_db()
        else:
            sys.exit()
    elif args.mode == "update_db":
        updater = DbUpdater(args.db_host, args.db_user, args.db_password, args.db_name)
        updater.update_db()
        print("Done populating database")

    if args.set_awake is not None:
        unset_keepawake()

main()