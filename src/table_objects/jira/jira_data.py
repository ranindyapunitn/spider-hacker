import datetime


class JiraData:

    def __init__(self):
        self.type = ""
        self.priority = ""
        self.affected_versions = []
        self.fix_versions = []
        self.components = []
        self.labels = []
        self.version_introduced = ""
        self.symptom_severity = ""
        self.status = ""
        self.resolution = ""
        #self.issue_summary = ""
        #self.expected_result = ""
        #self.actual_result = ""
        #self.workarounds = []
        self.attachments = []
        self.issue_links = []
        self.assignee = ""
        self.reporter = ""
        self.affected_customers = 0
        self.watchers = 0
        self.date_created = None
        self.date_updated = None
        self.date_resolved = None

