#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
import re

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):

    audit_JSON_field_mappings = {
        'description' : 'message',
        'eventTime' : 'timestamp',
        'eventId' : 'event_id',
        'loginName' : 'username',
        'orgName' : 'organization_name'
    }

    JSON_field_mappings = {
        'indicatorName' : 'indicator_name',
        'deviceName' : 'device_name',
        'policyName' : 'policy_name',
        'importance' : 'severity',
        'incidentId' : 'event_id',
        'summary' : 'message',
        'description' : 'message',
        'eventTime' : 'timestamp',
        'ruleName' : 'rule_name',
        'threatCategory' : 'threat_type',
        'internalIpAddress' : 'endpoint_ip',
        'externalIpAddress' : 'nat_translation',
        'targetPriorityType' : 'severity',
        'groupName' : 'group_name',
        'deviceType' : 'os_type',
        'deviceVersion' : 'os_version',
        'type' : 'category',
        'eventDescription' : 'description',
        'deviceId' : 'device_id',
        'actor' : 'file_sha256',
        'applicationName' : 'application'
    }

    def read_input_file(self, filename):
        with open(filename) as file:
            data = file.readlines()
        file.close()
        return json.loads(data[0])


    def cleanhtml(self, raw_html):
        cleanr = re.compile('<.*?>')
        cleantext = re.sub(cleanr, '', raw_html)
        return cleantext


    def cb_defense_server_request(self, url, path, api_key, connector_id, ssl_verify, proxies=None):
        self.ds.log('INFO', "Attempting to connect to url: " + url + path)
    
        headers = {'X-Auth-Token': "{0}/{1}".format(api_key, connector_id)}
        try:
            response = requests.get(url + path, headers=headers, timeout=15,
                                    verify=ssl_verify, proxies=proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        else:
            return response


    def cb_cloud_event_request(self, event_id, ssl_verify=True, proxies=None):
        alerts_url = self.url + "/api/investigate/v2/orgs/" + self.org_key + "/enriched_events/search_jobs"
        self.ds.log('INFO', "Attempting to connect to url: " + alerts_url)
        self.ds.log('INFO', "Getting enriched-events for id: " + event_id)

        request_body = {
                    "query": "event_id:" + event_id
                }

        headers = {'X-Auth-Token': "{0}/{1}".format(self.custom_api_key, self.custom_connector_id), 'Content-type':'application/json'}

        try:
            response = requests.post(alerts_url, headers=headers, data=json.dumps(request_body), timeout=15,
                                    verify=ssl_verify, proxies=proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(
                    alerts_url))
            return None
        else:
            json_results = response.json()
            job_id = json_results['job_id']

            path = "/api/investigate/v2/orgs/" + self.org_key + "/enriched_events/search_jobs/" + job_id + "/results"
            counter = 0
            while True:

                response = self.cb_defense_server_request(self.url,
            				     path,
                                             self.custom_api_key,
                                             self.custom_connector_id,
                                             True)
                if not response or response.status_code != 200:
                    self.ds.log('WARNING', 
                        "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(
                        self.ds.config_get('cb', 'server_url')))
                    return None

                json_response = json.loads(response.content)
                if json_response['completed'] == json_response['contacted']:
                    break
                elif counter > 30:
                    self.ds.log('WARNING', 
                        "Query did not complete in 60 seconds from Cb Defense Server {0}.".format(
                        self.ds.config_get('cb', 'server_url')))
                    return None
                else:
                    counter += 1
                    time.sleep(2)

            self.ds.log('INFO', "Received enriched-events count: " + str(len(json_response['results'])))
            return json_response['results'] 


    def cb_cloud_alerts_request(self, legacy_alert_id, ssl_verify=True, proxies=None):
        alerts_url = self.url + "/appservices/v6/orgs/" + self.org_key + "/alerts/_search"
        self.ds.log('INFO', "Attempting to connect to url: " + alerts_url)

        request_body = {
                "criteria": {
                    "legacy_alert_id": [legacy_alert_id]
                    }
                }
        headers = {'X-Auth-Token': "{0}/{1}".format(self.custom_api_key, self.custom_connector_id), 'Content-type':'application/json'}

        try:
            response = requests.post(alerts_url, headers=headers, data=json.dumps(request_body), timeout=15,
                                    verify=ssl_verify, proxies=proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(
                    alerts_url))
            return None
        else:
            return response.json()['results']

    def parse_cb_defense_response_cef(self, response):
        splitDomain = True
    
        log_messages = []
    
        if u'success' not in response:
            return log_messages
    
        if response[u'success']:
    
            if len(response[u'notifications']) < 1:
                #self.ds.log('INFO', 'successfully connected, no alerts at this time')
                return None
    
            for note in response[u'notifications']:
                entry = {}
                if 'type' not in note:
                    note['type'] = 'THREAT'
    
                if note['type'] == 'THREAT':

                    # Handle threatInfo
                    for key in note['threatInfo'].keys():
                        note[key] = note['threatInfo'][key]
                    del note['threatInfo']
                    del note['indicators']

                    # Handle threatCause
                    for key in note['threatCause'].keys():
                        note[key] = note['threatCause'][key]
                    del note['threatCause']

                    # Handle deviceInfo
                    for key in note['deviceInfo'].keys():
                        note[key] = note['deviceInfo'][key]
                    del note['deviceInfo']

                    device_name = str(note['deviceName'])
                    user_name = str(note['email'])
                    if '\\' in device_name and splitDomain:
                        (domain_name, device) = device_name.split('\\')
                        note['domainName'] = domain_name
                        note['deviceName'] = device
                    else:
                        note['deviceName'] = device_name
   
                    if '\\' in user_name and splitDomain:
                        (domain_name, user) = user_name.split('\\')
                        note['userName'] = user
                    else:
                        note['userName'] = user_name

                    if 'time' in note.keys():
                        del note['time']
    
                    #entry['act'] = 'Alert'
    
                elif note['type'] == 'POLICY_ACTION':

                    # Handle policyAction
                    for key in note['policyAction'].keys():
                        note[key] = note['policyAction'][key]
                    del note['policyAction']

                    for key in note['deviceInfo'].keys():
                        note[key] = note['deviceInfo'][key]
                    del note['deviceInfo']

                else:
                    continue
                entry['type'] = 'notification'
                log_messages.append(note)
                '''
                for item in note_indicators:
                    log_messages.append(item)
                '''
        return log_messages

    def cb_defense_siem_events(self):
        # Handle SIEM Connector
        response = self.cb_defense_server_request(self.url,
            				     '/integrationServices/v3/notification',
                                             self.siem_api_key,
                                             self.siem_connector_id,
                                             True)
        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(
                    self.ds.config_get('cb', 'server_url')))
            return None
        json_response = json.loads(response.content)
        #with open("notification.input", "w") as notifications:
            #notifications.write(json.dumps(json_response))
        #json_response = self.read_input_file("notification.input")

        #
        # parse the Cb Defense Response and get a list of log messages to send
        #
        log_messages = self.parse_cb_defense_response_cef(json_response)
        return log_messages

    def cb_defense_audit_events(self):
        # Handle AUDIT Connector
        audit_url = self.url + '/integrationServices/v3/auditlogs'
        response = self.cb_defense_server_request(self.url,
                                             '/integrationServices/v3/auditlogs',
                                             self.api_key,
                                             self.api_connector_id,
                                             True)

        if not response:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(audit_url))
            return None
        json_response = json.loads(response.content)
        #with open("audit.input", "w") as notifications:
        #    notifications.write(json.dumps(json_response))
        #json_response = self.read_input_file("audit.input")

        log_messages = []
        if u'success' not in json_response.keys():
            return log_messages
        if json_response[u'success']:
            if len(json_response[u'notifications']) < 1:
                #self.ds.log('INFO', 'successfully connected, no audit logs at this time')
                return None
        entry = {}
        audit_events = []
        for log in json_response['notifications']:
            entry = log
            entry['type'] = 'audit events'
            audit_events.extend([entry])
            
        return audit_events

    def cb_main(self): 

        self.url = self.ds.config_get('cb', 'server_url')
        self.org_key = self.ds.config_get('cb', 'org_key')
        self.api_key = self.ds.config_get('cb_api', 'api_key')
        self.api_connector_id = self.ds.config_get('cb_api', 'connector_id')
        self.siem_api_key = self.ds.config_get('cb_siem', 'api_key')
        self.siem_connector_id = self.ds.config_get('cb_siem', 'connector_id')
        self.custom_api_key = self.ds.config_get('cb_custom', 'api_key')
        self.custom_connector_id = self.ds.config_get('cb_custom', 'connector_id')
        self.max_run_time = int(self.ds.config_get('cb', 'max_run_time'))

        siem_log_messages = self.cb_defense_siem_events()

        alert_events = None
        event_details = []

        if siem_log_messages == None:
            self.ds.log('INFO', "There are no notifications to send")
        else:
            self.ds.log('INFO', "Sending {0} notifications".format(len(siem_log_messages)))

            for log in siem_log_messages:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.JSON_field_mappings)

        audit_log_messages = self.cb_defense_audit_events()

        if audit_log_messages == None:
            self.ds.log('INFO', "There are no audit logs to send")
        else:
            self.ds.log('INFO', "Sending {0} audit logs".format(len(audit_log_messages)))
            for log in audit_log_messages:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.audit_JSON_field_mappings)

        if siem_log_messages != None:
            timer_exceeded = False
            for notification in siem_log_messages:
                notification['type'] = 'threat_details'
                notification['summary'] = 'Details - ' + notification['summary']
                if timer_exceeded or (time.time() > (self.ds.start + self.max_run_time)):
                    timer_exceeded = True
                    self.ds.log('INFO', 'Timer Exceeded.  Skipping ' + notification['causeEventId'])
                    notification['event_description'] = 'Timer Exceeded.  No extended details available'
                    self.ds.writeJSONEvent(notification, JSON_field_mappings = self.JSON_field_mappings)
                    continue
                if 'incidentId' not in notification.keys():
                    self.ds.log('INFO', "Notification missing incidentId")
                    continue
                if 'causeEventId' not in notification.keys():
                    self.ds.log('INFO', "Notification missing causeEventId")
                    continue
                events = []
                counter = 0
                while len(events) == 0 and counter < 5:
                    if timer_exceeded or (time.time() > (self.ds.start + self.max_run_time)):
                        timer_exceeded = True
                        self.ds.log('INFO', 'Timer Exceeded.  Skipping ' + notification['causeEventId'])
                        notification['event_description'] = 'Timer Exceeded.  No extended details available'
                        break
                    events = self.cb_cloud_event_request(event_id = notification['causeEventId'])
                    print(len(events))
                    if len(events) == 0:
                        time.sleep(2)
                        counter = counter + 1
                if len(events) > 0:
                    if 'process_name' in events[0].keys():
                        notification['process_name'] = events[0]['process_name']
                    else:
                        self.ds.log('INFO', "Event missing process_name")
                    if 'event_description' in events[0].keys():
                        notification['event_description'] = self.cleanhtml(events[0]['event_description'])
                    else:
                        self.ds.log('INFO', "Event missing event_description")
                else:
                    self.ds.log('INFO', "No Events found for notification")

                self.ds.writeJSONEvent(notification, JSON_field_mappings = self.JSON_field_mappings)

        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('cb', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.cb_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('cbcloudendpointEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
