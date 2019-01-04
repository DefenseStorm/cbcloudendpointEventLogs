#!/usr/bin/env python

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests

from DefenseStorm import DefenseStorm

class integration(object):


    def get_audit_logs(self, url, api_key_query, connector_id_query, ssl_verify, proxies=None):
        headers = {'X-Auth-Token': "{0}/{1}".format(api_key_query, connector_id_query)}
        try:
            response = requests.get("{0}/integrationServices/v3/auditlogs".format(url),
                                    headers=headers,
                                    timeout=15, proxies=proxies)
    
            if response.status_code != 200:
                self.ds.log('ERROR', "Could not retrieve audit logs: {0}".format(response.status_code))
                return False
    
            notifications = response.json()
        except Exception as e:
            self.ds.log('ERROR', "Exception {0} when retrieving audit logs".format(str(e)))
            return None
    
        if notifications.get("success", False) != True:
            self.ds.log('ERROR', "Unsuccessful HTTP response retrieving audit logs: {0}"
                         .format(notifications.get("message")))
            return False
    
        notifications = notifications.get("notifications", [])
        if not notifications:
            self.ds.log('INFO', "No audit logs available")
            return False
    
        return notifications
    
    def cb_defense_server_request(self, url, api_key, connector_id, ssl_verify, proxies=None):
        self.ds.log('INFO', "Attempting to connect to url: " + url)
    
        headers = {'X-Auth-Token': "{0}/{1}".format(api_key, connector_id)}
        try:
            response = requests.get(url + '/integrationServices/v3/notification', headers=headers, timeout=15,
                                    verify=ssl_verify, proxies=proxies)
            self.ds.log('INFO', response)
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
                self.ds.log('INFO', 'successfully connected, no alerts at this time')
                return None
    
            for note in response[u'notifications']:
                if 'type' not in note:
                    note['type'] = 'THREAT'
    
                if note['type'] == 'THREAT':
                    signature = 'Active_Threat'
                    seconds = str(note['eventTime'])[:-3]
                    name = str(note['threatInfo']['summary'])
                    severity = str(note['threatInfo']['score'])
                    device_name = str(note['deviceInfo']['deviceName'])
                    user_name = str(note['deviceInfo']['email'])
                    device_ip = str(note['deviceInfo']['internalIpAddress'])
                    link = str(note['url'])
                    tid = str(note['threatInfo']['incidentId'])
                    timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                    extension = ''
                    extension += 'rt="' + timestamp + '"'
    
                    if '\\' in device_name and splitDomain:
                        (domain_name, device) = device_name.split('\\')
                        extension += ' sntdom=' + domain_name
                        extension += ' dvchost=' + device
                    else:
                        extension += ' dvchost=' + device_name
    
                    if '\\' in user_name and splitDomain:
                        (domain_name, user) = user_name.split('\\')
                        extension += ' duser=' + user
                    else:
                        extension += ' duser=' + user_name
    
                    extension += ' dvc=' + device_ip
                    extension += ' cs3Label="Link"'
                    extension += ' cs3="' + link + '"'
                    extension += ' cs4Label="Threat_ID"'
                    extension += ' cs4="' + tid + '"'
                    extension += ' act=Alert'
    
                elif note['type'] == 'POLICY_ACTION':
                    signature = 'Policy_Action'
                    name = 'Confer Sensor Policy Action'
                    severity = policy_action_severity
                    seconds = str(note['eventTime'])[:-3]
                    timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                    device_name = str(note['deviceInfo']['deviceName'])
                    user_name = str(note['deviceInfo']['email'])
                    device_ip = str(note['deviceInfo']['internalIpAddress'])
                    sha256 = str(note['policyAction']['sha256Hash'])
                    action = str(note['policyAction']['action'])
                    app_name = str(note['policyAction']['applicationName'])
                    link = str(note['url'])
                    extension = ''
                    extension += 'rt="' + timestamp + '"'
                    if '\\' in device_name and splitDomain == True:
                        (domain_name, device) = device_name.split('\\')
                        extension += ' sntdom=' + domain_name
                        extension += ' dvchost=' + device
                    else:
                        extension += ' dvchost=' + device_name
    
                    if '\\' in user_name and splitDomain == True:
                        (domain_name, user) = user_name.split('\\')
                        extension += ' duser=' + user
                    else:
                        extension += ' duser=' + user_name
    
                    extension += 'rt="' + timestamp + '"'
                    extension += ' dvc=' + device_ip
                    extension += ' cs3Label="Link"'
                    extension += ' cs3="' + link + '"'
                    extension += ' act=' + action
                    extension += ' hash=' + sha256
                    extension += ' deviceprocessname=' + app_name
    
                else:
                    continue
    
                log_messages.append({'version': version,
                                     'vendor': vendor,
                                     'product': product,
                                     'dev_version': dev_version,
                                     'signature': signature,
                                     'name': name,
                                     'severity': severity,
                                     'extension': extension,
                                     'source': source})
        return log_messages


    def cb_main(self): 
        response = self.cb_defense_server_request(self.ds.config_get('cbdefense', 'server_url'),
                                             self.ds.config_get('cbdefense', 'api_key'),
                                             self.ds.config_get('cbdefense', 'connector_id'),
                                             True)

        if not response:
            self.ds.log('WARNING', 
                    "Received unexpected (or no) response from Cb Defense Server {0}.".format(
                    self.ds.config_get('cbdefense', 'server_url')))
            return

        #
        # perform fixups
        #
        # logger.debug(response.content)
        json_response = json.loads(response.content)

        #
        # parse the Cb Defense Response and get a list of log messages to send to tcp_tls_host:tcp_tls_port
        #
        log_messages = self.parse_cb_defense_response_cef(json_response)

        if not log_messages:
            self.ds.log('INFO', "There are no messages to forward to host")
        else:
            self.ds.log('INFO', "Sending {0} messages to {1}:{2}".format(len(log_messages),
                                                                 output_params['output_host'],
                                                                 output_params['output_port']))
            #
            # finally send the messages
            #
            for log in log_messages:

                template = "{{source}}|{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}"
                final_data = template.render(log)

                self.ds.writeEvent(final_data)

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
