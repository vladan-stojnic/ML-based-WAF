'''Implementation of the logic for representing the requests and logging them.'''

import datetime
import sqlite3
import pandas as pd
import json
import os

class Request(object):
    def __init__(self, id = None, timestamp = None, origin = None, host = None, request = None, body = None, method = None, headers = None, threats = None):
        self.id = id
        self.timestamp = timestamp
        self.origin = origin
        self.host = host
        self.request = request
        self.body = body
        self.method = method
        self.headers = headers
        self.threats = threats

    def to_json(self):
        output = {}

        if self.request != None and self.request != '':
            output['request'] = self.request

        if self.body != None and self.body != '':
            output['body'] = self.body

        if self.headers != None:
            for header, value in self.headers.items():
                output[header] = value

        return json.dumps(output)

class DBController(object):
    def __init__(self):
        self.conn = sqlite3.connect("log.db")
        self.conn.row_factory = sqlite3.Row
    
    def save(self, obj):
        if not isinstance(obj, Request):
            raise TypeError("Object should be a Request!!!")

        cursor = self.conn.cursor()

        obj.timestamp = datetime.datetime.now()

        cursor.execute("INSERT INTO logs (timestamp, origin, host, method) VALUES (?, ?, ?, ?)", 
                        (obj.timestamp, obj.origin, obj.host, obj.method))

        obj.id = cursor.lastrowid

        file_name = str(obj.id) + '.json'
        file_path = os.path.join('requests_log', file_name)

        with open(file_path, 'w') as f:
            json.dump(json.loads(obj.to_json()), f)

        for threat, location in obj.threats.items():
            cursor.execute("INSERT INTO threats (log_id, threat_type, location) VALUES (?, ?, ?)", (obj.id, threat, location))

        self.conn.commit()

    def __create_entry(self, row):
        entry = dict(row)
        entry['Link'] = '[Review](http://127.0.0.1:8050/review/'+str(entry['id'])+')'

        return entry

    def read_all(self):
        cursor = self.conn.cursor()

        cursor.execute("SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id")

        results = cursor.fetchall()

        data = [self.__create_entry(row) for row in results]

        return pd.DataFrame(data)

    def __create_single_entry(self, row):
        return [row['threat_type'], row['location']]

    def read_request(self, id):
        cursor = self.conn.cursor()

        #print(type(id))

        cursor.execute("SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id WHERE l.id = ?", (id,))

        results = cursor.fetchall()

        log = {}

        if len(results) != 0:
            log['timestamp'] = results[0]['timestamp']
            log['origin'] = results[0]['origin']
            log['host'] = results[0]['host']
            log['method'] = results[0]['method']

        data = [self.__create_single_entry(row) for row in results]

        return log, data

    def close(self):
        self.conn.close()