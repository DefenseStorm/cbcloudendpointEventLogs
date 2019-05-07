#!/usr/bin/env python

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

sys.path.insert(0, '/usr/local/cbdefenseEventLogs/ds-integration')
from DefenseStorm import DefenseStorm

from HTMLParser import HTMLParser

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


def flatten_json(y):
    out = {}

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name + str(i) + '_')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(y)
    return out

class integration(object):

    auditlogs_CEF_field_mappings = {
        'requestUrl': 'cs4',
        'eventTime': 'rt',
        'eventId': 'cs1',
        'loginName': 'cs2',
        'orgName': 'cs3',
        'flagged': None,
        'clientIp': 'src',
        'verbose': None,
        'description': 'name',
        'category': 'cs5'
    }

    auditlogs_CEF_custom_field_labels = {
        'cs1Label' : 'eventId',
        'cs2Label' : 'loginName',
        'cs3Label' : 'orgName',
        'cs4Label' : 'requestUrl',
        'cs5Label' : 'category',
        'cs6Label' : None,
        'cn1Label' : None,
        'cn2Label' : None,
        'cn3Label' : None,
        'flexDate1Label' : None,
        'flexString1Label' : None,
        'flexString2Label' : None
    }

    notifications_CEF_field_mappings = {
        'link': 'cs1',
        'threat_id': 'cs2',
        'alert_id': 'cs3',
        'rt': 'rt',
        'severity': 'severity',
        'act': 'act',
        'dvc': 'dvc',
        'dvchost': 'dvchost',
        'name': 'name',
        'signature': 'type',
        'duser': 'duser',
        'dom': 'dom',
        'sntdom': 'sntdom',
        'category': 'cs4'
    }
    notifications_CEF_custom_field_labels = {
        'cs1Label' : 'link',
        'cs2Label' : 'threat_id',
        'cs3Label' : 'alert_id',
        'cs4Label' : 'category',
        'cs5Label' : None,
        'cs6Label' : None,
        'cn1Label' : None,
        'cn2Label' : None,
        'cn3Label' : None,
        'flexDate1Label' : None,
        'flexString1Label' : None,
        'flexString2Label' : None
    }

    def read_input_file(self, filename):
        with open(filename) as file:
            data = file.readlines()
        file.close()
        return json.loads(data[0])


    def cb_defense_server_request(self, url, path, api_key, connector_id, ssl_verify, proxies=None):
        #self.ds.log('INFO', "Attempting to connect to url: " + url + path)
    
        headers = {'X-Auth-Token': "{0}/{1}".format(api_key, connector_id)}
        try:
            response = requests.get(url + path, headers=headers, timeout=15,
                                    verify=ssl_verify, proxies=proxies)
            #self.ds.log('INFO', response)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
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
                    entry['signature'] = 'Active_Threat'
                    entry['rt'] = str(note['eventTime'])
                    entry['name'] = str(note['threatInfo']['summary'])
                    entry['severity'] = str(note['threatInfo']['score'])
                    device_name = str(note['deviceInfo']['deviceName'])
                    user_name = str(note['deviceInfo']['email'])
                    entry['dvc'] = str(note['deviceInfo']['internalIpAddress'])
                    entry['link'] = str(note['url'])
                    entry['threat_id'] = str(note['threatInfo']['incidentId'])
                    entry['alert_id'] = str(note['threatInfo']['incidentId'])
    
                    if '\\' in device_name and splitDomain:
                        (domain_name, device) = device_name.split('\\')
                        entry['sntdom'] = domain_name
                        entry['dvchost'] = device
                    else:
                        entry['dvchost'] = device_name
    
                    if '\\' in user_name and splitDomain:
                        (domain_name, user) = user_name.split('\\')
                        entry['duser'] = user
                    else:
                        entry['duser'] = user_name
    
                    entry['act'] = 'Alert'
    
                elif note['type'] == 'POLICY_ACTION':
                    entry['signature'] = 'Policy_Action'
                    entry['name'] = 'Confer Sensor Policy Action'
                    entry['severity'] = 4
                    entry['rt'] = str(note['eventTime'])
                    entry['device_name'] = str(note['deviceInfo']['deviceName'])
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
    
                else:
                    continue
                entry['category'] = 'notification'
                log_messages.append(entry)
        return log_messages

    def cb_defense_siem_events(self):
        # Handle SIEM Connector
        response = self.cb_defense_server_request(self.ds.config_get('cbdefense', 'server_url'),
            				     '/integrationServices/v3/notification',
                                             self.ds.config_get('cbdefense_siem', 'api_key'),
                                             self.ds.config_get('cbdefense_siem', 'connector_id'),
                                             True)
        if not response:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(
                    self.ds.config_get('cbdefense', 'server_url')))
            return None
        json_response = json.loads(response.content)
        #self.ds.log('DEBUG', json.dumps(json_response))
        #json_response = self.read_input_file("notification.input")

        #
        # parse the Cb Defense Response and get a list of log messages to send
        #
        log_messages = self.parse_cb_defense_response_cef(json_response)
        return log_messages

    def cb_defense_alert_details(self, alert_id):
        # Handle AUDIT Connector
        response = self.cb_defense_server_request(self.ds.config_get('cbdefense', 'server_url'),
                                             '/integrationServices/v3/alert/' + alert_id,
                                             self.ds.config_get('cbdefense_api', 'api_key'),
                                             self.ds.config_get('cbdefense_api', 'connector_id'),
                                             True)
        json_response = json.loads(response.content)
        #self.ds.log('DEBUG', json.dumps(json_response))
        alert_details = {}

        if u'success' not in json_response.keys():
            return None
        if json_response[u'success']:
            alert_details['deviceInfo'] = json_response['deviceInfo']
            alert_details['events'] = json_response['events']
            alert_details['threatInfo'] = json_response['threatInfo']
            return alert_details
        return None

    def cb_defense_audit_events(self):
        # Handle AUDIT Connector
        response = self.cb_defense_server_request(self.ds.config_get('cbdefense', 'server_url'),
                                             '/integrationServices/v3/auditlogs',
                                             self.ds.config_get('cbdefense_api', 'api_key'),
                                             self.ds.config_get('cbdefense_api', 'connector_id'),
                                             True)

        if not response:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(
                    self.ds.config_get('cbdefense', 'server_url')))
            return None

        json_response = json.loads(response.content)
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

        audit_log_messages = self.cb_defense_audit_events()
        siem_log_messages = self.cb_defense_siem_events()

        alert_details_messages = []
        #siem_log_messages = [{'alert_id':'T1SNCENR'}]
        if siem_log_messages != None:
            for log in siem_log_messages:
                alert_details = self.cb_defense_alert_details(log['alert_id'])
                if alert_details != None:

                    # Handle deviceInfo
                    this_alert = {}
                    for key in alert_details['deviceInfo'].keys():
                        this_alert[key] = alert_details['deviceInfo'][key]
                    this_alert['device_message'] = this_alert['message']
                    this_alert['message'] = "Device Info for Alert ID: " + log['alert_id']
                    alert_details_messages.extend([this_alert])

                    # Handle Events
                    for item in alert_details['events']:
                        this_item = {}
                        for key in item.keys():
                            this_item[key] = item[key]
                        this_item['message'] = "Event Info for Alert ID: " + log['alert_id']
                        alert_details_messages.extend([this_item])

                    # Handle threatInfo
                    this_item = {}
                    this_item['message'] = "Threat Info for Alert ID: " + log['alert_id']
                    for key in alert_details['threatInfo'].keys():
                        this_item[key] = alert_details['threatInfo'][key]
                    del this_item['indicators']
                    alert_details_messages.extend([this_item])

                    # Handle threatInfo indicators
                    for item in alert_details['threatInfo']['indicators']:
                        this_item = {}
                        this_item['message'] = "Threat Info Indicators for Alert ID: " + log['alert_id'] + " Threat ID: " + alert_details['threatInfo']['threatId']
                        for key in item.keys():
                            this_item[key] = item[key]
                        alert_details_messages.extend([this_item])

                    alert_details['message'] = "Alert Details for alert ID: " + log['alert_id']
                    alert_details_messages.extend([alert_details])


        #siem_log_messages = None
  
        if audit_log_messages == None:
            self.ds.log('INFO', "There are no audit logs to send")
        else:
            self.ds.log('INFO', "Sending {0} audit logs".format(len(audit_log_messages)))
            for log in audit_log_messages:
                self.ds.writeCEFEvent(type='Audit Log', dataDict=log, CEF_field_mappings=self.auditlogs_CEF_field_mappings, CEF_custom_field_labels=self.auditlogs_CEF_custom_field_labels)
                #self.ds.writeEvent(json.dumps(log))

        if siem_log_messages == None:
            self.ds.log('INFO', "There are no notifications to send")
        else:
            self.ds.log('INFO', "Sending {0} notifications".format(len(siem_log_messages)))

            for log in siem_log_messages:
                self.ds.writeCEFEvent(type='policy_action', dataDict=log, CEF_field_mappings=self.notifications_CEF_field_mappings, CEF_custom_field_labels=self.notifications_CEF_custom_field_labels)

        if len(alert_details_messages) > 0:
            for log in alert_details_messages:
                self.ds.writeJSONEvent(json.loads(strip_tags(json.dumps(flatten_json(log)))))

        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('cbdefense', 'pid_file')
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
        print os.path.basename(__file__)
        print
        print '  No Options: Run a normal cycle'
        print
        print '  -t    Testing mode.  Do all the work but do not send events to GRID via '
        print '        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\''
        print '        in the current directory'
        print
        print '  -l    Log to stdout instead of syslog Local6'
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
            self.ds = DefenseStorm('cbdefenseEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception ,e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
