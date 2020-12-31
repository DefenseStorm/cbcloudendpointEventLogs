CB Cloud Endpoint (formerly CB Defense)for DefenseStorm

This integration provides several enhancements over the integration provided in the CB provided cbc_syslog.  Specifically:

- Additional request is made to the API to pull the process_name and 
  event_desciption from the associate causeEventId and include that
  information with the notification

- Add data is sent to GRID in JSON format


to pull this repository and submodules:

git clone --recurse-submodules https://github.com/DefenseStorm/cbcloudendpointEventLogs.git

1. If this is the first integration on this DVM, Do the following:

  cp ds-integration/ds_events.conf /etc/syslog-ng/conf.d

  Edit /etc/syslog-ng/syslog-ng.conf and add local7 to the excluded list for filter f_syslog3 and filter f_messages. The lines should look like the following:

filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };

filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news,local7); };


  Restart syslog-ng
    service syslog-ng restart

2. Copy the template config file and update the settings

  cp cbcloudendpointEventLogs.conf.template cbcloudendpointEventLogs.conf

  change the following items in the config file based on your configuration

  The first two settings are for your organization.  The server_url is the base URL for accessing
  the CB Cloud web interface.  The org_key is your org_key as shows on the Settings-API
  configuraiton screen.

	org_key    
	server_url

  You will need to generate 3 pairs of Connector IDs and API Keys:
    (1) Access Level Type: API - this for audit log data
    (2) Access Level Type: SIEM - this for notifications
    (3) Access Level Type: Custom - this for additional event data.  Addionally for this key
        you will need to configure the Access Levels for this custom key.  You need Category 
        Alerts, Permission General Information and READ access and Query Create and Read Create this Access Level before
        creating the custom API key.

  Put the appropriate connector_id and api_key in each of the 3 sections in the conf file's
	connector_id
	api_key

3. Add the following entry to the root crontab so the script will run every
   5 minutes

   */5 * * * * cd /usr/local/cbcloudendpointEventLogs; ./cbcloudendpointEventLogs.py
