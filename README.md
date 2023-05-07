## About

spider-hacker is a tool written in python with the goal of building a database of known software vulnerabilities by scraping data from four major web sources: [NVD](https://nvd.nist.gov/), [CveDetails](https://www.cvedetails.com/), [Snyk](https://snyk.io/) and [Jira](https://jira.atlassian.com/issues/). The data is then saved into a MySql database.

## Usage

#### Prerequisites

1. [Python 3](https://www.python.org/)
2. [setuptools](https://pypi.org/project/setuptools/) (for installation)
3. [MySql](https://dev.mysql.com/downloads/)

#### Dependencies (installed atuomatically)

1. [beautifulsoup](https://pypi.org/project/beautifulsoup4/)
2. [selenium](https://pypi.org/project/selenium/)
3. [grequests](https://github.com/spyoungtech/grequests)
4. [mysql-connector](https://pypi.org/project/mysql-connector-python/)
5. [alive-progress](https://pypi.org/project/alive-progress/)

#### Installation

1. Clone the repository: ```git clone https://github.com/mgiambi/spider-hacker```
2. Move into the project folder and install the tool with the command: ```python setup.py install```
3. Create an empty MySql schema to populate with the data

#### Basic usage

If you successfullt completed the installation, you can run the tool from the terminal with the command ```spider-hacker```. You also need to add a few parameters, which are, in order:

 1. ```mode```: the mode you wish to run. There are five of them:
     1. ```create_db```: creates the tables and database structure. Note that this operation erases all previous existing data. 
     2. ```delete_db```: deletes all rows from all tables.
     3. ```dump_db```: dumps the content of the database into a csv file (currently not working)
     4. ```populate_cache```: crawls the source websites for the list of existing CVE and the corresponding links, then populates a "cache" table.
     5. ```update_db```: gets the CVE links from the cache table and scrapes the corresponding web pages for the info, then saves them in the database.
 2. ```db_host```: the IP address where the database is located.
 3. ```db_user```: the username to access the database.
 4. ```db_password```: the password to access the database.
 5. ```db_name```: the name of the schema.
 6. ```clear_cache``` (optional): if ```populate_cache``` mode is chosen, this parameter can be set to clear the cache table of all pre-existing entries.
 7. ```set_awake``` (optional): if set, the host will never go on standby. Since the tool runs for very long, this is recommended in order to not stop the execution. 

## License

This project is licensed under the [GPL 3.0 License](https://www.gnu.org/licenses/gpl-3.0.en.html).

