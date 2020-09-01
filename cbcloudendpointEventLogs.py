#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()

class integration(object):

    audit_JSON_field_mappings = {
        'description' : 'message',
        'eventTime' : 'timestamp',
        'eventId' : 'event_id',
        'loginName' : 'username',
        'orgName' : 'organization'
    }

    JSON_field_mappings = {
        'indicatorName' : 'indicator_name',
        'applicationName' : 'application',
        'threatScore' : 'threat_score',
        'deviceName' : 'device_name',
        'policyName' : 'policy_name',
        'importance' : 'severity',
        'incidentId' : 'event_id',
        'summary' : 'message',
        'eventTime' : 'timestamp',
        'ruleName' : 'rule_name',
        'threatCategory' : 'threat_type',
        'internalIpAddress' : 'ip_local',
        'externalIpAddress' : 'nat_translation',
        'targetPriorityType' : 'severity',
        'groupName' : 'group_name',
        'deviceType' : 'os_type',
        'deviceVersion' : 'os_version',
        'type' : 'category'
    }

    def read_input_file(self, filename):
        with open(filename) as file:
            data = file.readlines()
        file.close()
        return json.loads(data[0])


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
                    alert_url))
            return None
        else:
            return response
    
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
                    this_item = {}
                    #this_item['message'] = "Threat Indicators for Alert ID: " + log['alert_id']
                    for key in note['threatInfo'].keys():
                        note[key] = note['threatInfo'][key]
                    del note['threatInfo']


                    # Handle threat indicators
                    note_indicators = []
                    for ti in note['indicators']:
                        this_item = {}
                        this_item['message'] = "Threat Indicators for Alert ID: " + note['incidentId']
                        this_item['event_id'] = note['incidentId']
                        for key in ti.keys():
                            this_item[key] = ti[key]
                        note_indicators.extend([this_item])
                    del note['indicators']

                    # Handle threatCause
                    this_item = {}
                    #this_item['message'] = "Threat Indicators for Alert ID: " + log['alert_id']
                    for key in note['threatCause'].keys():
                        note[key] = note['threatCause'][key]
                    del note['threatCause']

                    # Handle deviceInfo
                    this_item = {}
                    #this_item['message'] = "Threat Indicators for Alert ID: " + log['alert_id']
                    for key in note['deviceInfo'].keys():
                        note[key] = note['deviceInfo'][key]
                    del note['deviceInfo']

                    '''
                    entry['signature'] = 'Active_Threat'
                    entry['rt'] = str(note['eventTime'])
                    entry['name'] = str(note['threatInfo']['summary'])
                    entry['severity'] = str(note['threatInfo']['score'])
                    entry['dvc'] = str(note['deviceInfo']['internalIpAddress'])
                    entry['link'] = str(note['url'])
                    entry['threat_id'] = str(note['threatInfo']['incidentId'])
                    entry['alert_id'] = str(note['threatInfo']['incidentId'])
                    '''
    
                    device_name = str(note['deviceName'])
                    user_name = str(note['email'])
                    if '\\' in device_name and splitDomain:
                        (domain_name, device) = device_name.split('\\')
                        note['domainName'] = domain_name
                        note['deviceName'] = device
                    else:
                        note['deviceName'] = device_name
   
                    '''
                    if '\\' in user_name and splitDomain:
                        (domain_name, user) = user_name.split('\\')
                        note['userName'] = user
                    else:
                        note['userName'] = user_name
                    '''
    
                    #entry['act'] = 'Alert'
    
                elif note['type'] == 'POLICY_ACTION':

                    # Handle policyAction
                    this_item = {}
                    #this_item['message'] = "Threat Indicators for Alert ID: " + log['alert_id']
                    for key in note['policyAction'].keys():
                        note[key] = note['policyAction'][key]
                    del note['policyAction']

                    '''
                    entry['signature'] = 'Policy_Action'
                    entry['name'] = 'Confer Sensor Policy Action'
                    entry['severity'] = 4
                    entry['rt'] = str(note['eventTime'])
                    entry['device_name'] = str(note['deviceInfo']['deviceName'])
                    device_name = str(note['deviceInfo']['deviceName'])
                    user_name = str(note['deviceInfo']['email'])
                    entry['device_ip'] = str(note['deviceInfo']['internalIpAddress'])
                    entry['hash'] = str(note['policyAction']['sha256Hash'])
                    entry['act'] = str(note['policyAction']['action'])
                    entry['deviceprocessname'] = str(note['policyAction']['applicationName'])
                    link = str(note['url'])
                   
                    if '\\' in device_name and splitDomain == True:
                        (domain_name, device) = device_name.split('\\')
                        entry['sntdom'] = domain_name
                        entry['dvchost'] = device
                    else:
                        entry['dvchost'] = device_name
    
                    if '\\' in user_name and splitDomain == True:
                        (domain_name, user) = user_name.split('\\')
                        entry['duser'] = user
                    else:
                        entry['duser'] = user_name
    
                    entry['dvc'] = entry['device_ip']
                    entry['link'] = link
                    #entry['threat_id'] =  get_unicode_string(note['threatInfo']['incidentId'])
                    entry['deviceprocessname'] = get_unicode_string(note['policyAction']['applicationName'])
                    '''
    
                else:
                    continue
                entry['category'] = 'notification'
                log_messages.append(note)
                for item in note_indicators:
                    log_messages.append(item)
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

    def cb_defense_alert_details(self, alert_id):
        # Handle AUDIT Connector
        response = self.cb_cloud_alerts_request(legacy_alert_id = alert_id)
        if not response:
            return None

        json_response = json.loads(response.content)['results']

        #with open("alert_details.input", "w") as notifications:
            #notifications.write(json.dumps(json_response))

        return json_response

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
            entry['category'] = 'audit events'
            audit_events.extend([entry])
            
        return audit_events

    def cb_main(self): 

        #alert_details = self.cb_defense_alert_details('FV8GRSC7')

        self.url = self.ds.config_get('cb', 'server_url')
        self.org_key = self.ds.config_get('cb', 'org_key')
        self.api_key = self.ds.config_get('cb_api', 'api_key')
        self.api_connector_id = self.ds.config_get('cb_api', 'connector_id')
        self.siem_api_key = self.ds.config_get('cb_siem', 'api_key')
        self.siem_connector_id = self.ds.config_get('cb_siem', 'connector_id')
        self.custom_api_key = self.ds.config_get('cb_custom', 'api_key')
        self.custom_connector_id = self.ds.config_get('cb_custom', 'connector_id')

        audit_log_messages = self.cb_defense_audit_events()
        siem_log_messages = self.cb_defense_siem_events()

        '''
        alert_details_messages = []
        #siem_log_messages = [{'alert_id':'T1SNCENR'}]
        if siem_log_messages != None:
            for log in siem_log_messages:
                print(json.dumps(log))
                alert_details = self.cb_defense_alert_details(log['incidentId'])
                if alert_details != None:
                    for item in alert_details:

                        # Handle threat indicators
                        this_item = {}
                        this_item['message'] = "Threat Indicators for Alert ID: " + log['incidentId']
                        for ti in item['threat_indicators']:
                            this_item = {}
                            for key in ti.keys():
                                this_item[key] = ti[key]
                            #del this_item['indicators']
                            alert_details_messages.extend([this_item])

                        item['message'] = "Alert Details for alert ID: " + log['incidentId']
                        item['incidentId'] = log['incidentId']
                        alert_details_messages.extend([item])
        '''

        if audit_log_messages == None:
            self.ds.log('INFO', "There are no audit logs to send")
        else:
            self.ds.log('INFO', "Sending {0} audit logs".format(len(audit_log_messages)))
            for log in audit_log_messages:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.audit_JSON_field_mappings)

        if siem_log_messages == None:
            self.ds.log('INFO', "There are no notifications to send")
        else:
            self.ds.log('INFO', "Sending {0} notifications".format(len(siem_log_messages)))

            for log in siem_log_messages:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.JSON_field_mappings)
        '''
        if len(alert_details_messages) > 0:
            self.ds.log('INFO', "Sending {0} alert details".format(len(alert_details_messages)))
            for log in alert_details_messages:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.JSON_field_mappings)
        '''

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
