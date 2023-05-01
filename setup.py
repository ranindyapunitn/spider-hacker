import pathlib
from setuptools import find_packages, setup

setup(
    name="spider-hacker",
    version="1.0.0",
    #long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/mgiambi/spider-hacker",
    author="Michael Giambi",
    author_email="michael.giambi@studenti.unitn.it",
    #license_files=('LICENSES/LICENSE.txt'),
    #package_dir = {'': 'src'},
    packages = find_packages(),
    #packages=["src", "src.db_manager", "src.hacker", "src.hacker.db_create", "src.hacker.db_delete", 
    #"src.hacker.db_dump", "src.hacker.db_update", "src.table_objects", "src.table_objects.cvedetails",
    #"src.table_objects.jira", "src.table_objects.nvd", "src.table_objects.snyk", "src.table_objects.vulnerability"],
    python_requires='>=3.7',
    #data_files=[("src/ldiff_wrapper/", ["src/ldiff_wrapper/lhdiff_2020.jar"])],
    install_requires=[
        "mysql-connector-python", "grequests", "selenium", "wakepy", "lxml"],
    entry_points={
        "console_scripts": [
            "spider-hacker=src.__main__:main",
        ]
    },
)