from db_manager.db_manager import DbManager
import mysql.connector
import numpy as np
import matplotlib.pyplot as plt
 

class Plotter:

    def __init__(self, hostname, user, password, schema_name):
        self.hostname = hostname
        self.user = user
        self.password = password
        self.schema_name = schema_name

    def plot(self):
        scores = []
        years = []
        manager = DbManager(self.hostname, self.user, self.password, self.schema_name)
        vulnerability_list = manager.get_vulnerabilities()

        for vuln in vulnerability_list:
            scores.append(vuln.snyk_data.snyk_score)
            years.append(vuln.snyk_data.snyk_published_date.year)

        fig, ax = plt.subplots(figsize=(5, 2.7), layout='constrained')
        ax.plot(scores, years, label='scores by year')
        #ax.plot(scores, x**2, label='quadratic') 
        #ax.plot(x, x**3, label='cubic')
        ax.set_xlabel('x label')
        ax.set_ylabel('y label')
        ax.set_title("Simple Plot")
        ax.legend()
        plt.show()