#!/usr/bin/env python
"""
PRE-REQUISITES:
   1.  Python 2.x
   2.  Install python-requests:
        a.  sudo easy_install requests
   3.  Go to dev.elbrys.com and follow the directions there

BUG/SUGGESTIONS:
Mail bug reports and suggestion to : support@elbrys.com
Bug reports may also be logged in github here:  https://github.com/Elbrys/ODL-S-Sample-Apps/issues


DESCRIPTION:
    This is an intermediate complexity application that utilizes multi-threading.

    The application is associated with the switch you configured on the command line.
     You must have configured that switch to use ODL-S as its openflow controller per 
     the instructions on dev.elbrys.com. Any endpoint that does not yet have an associated 
     policy (one you gave it using this application - see below) will be detected by ODL-S 
     and will cause ODL-S to generate an 'unmanaged endpoint' event.
    
    This application has created a subscription to ODL-S events.  It will receive events 
     from your switch.  IF ODL-S Event logging is ENABLED (see below): it will print a message to the screen 
     when it receives ODL-S events. When a new 'unmanaged endpoint' event occurs it will print a message to 
     the screen as well as add that endpoint to its list of known endpoints.  Event logging is disabled by default.
   
    All traffic for unmanaged endpoints will be blocked until you associate a policy to the endpoint.
  
    This application will allow you to view a list of all unmanaged endpoints and select 
     a target endpoint and then do any number of actions to that endpoint, including 
     associating a policy to it.
    
    While this application is running, you can go to your ODL-S dashboard (sdn-developer.elbrys.com) 
     and refresh the screen and you will see this application listed in the applications table.  In addition
     the switch you configured on the command line should indicate it is active on the ODL-S dashboard
     by being displayed in green.
    
    Enable ODL-S event logging, connect one or more user devices (laptop, tablet, phone) to ports on your network device. 
     After you connect the device, cause it to send network traffic (ping, web browse, etc) 
     You should see an ODL-S event indicating an 'unmanaged endpoint' with a MAC address 
     that matches the device you have connected to the switch (if ODL-S event logging is enabled).
"""

import sys, os, errno, signal 
import requests
import json
import time
import argparse
from requests.auth import HTTPBasicAuth
import threading
import Queue
import traceback

def interuppt_handler(signum, frame):
    sys.exit(-2) #Terminate process here as catching the signal removes the close process behaviour of Ctrl-C

signal.signal(signal.SIGINT, interuppt_handler)

 
def GetAuthToken(user, password):
    global odlsBaseUrl
    # This calls the  api to create an authorization token to make other calls
    # RETURNS: authorization token
    url = odlsBaseUrl + '/auth/token'
    print "GetAuthToken: " + odlsBaseUrl
    headers = {'content-type': 'application/json'}
    user = "name="+user
    appId = requests.get(url, headers=headers, auth=HTTPBasicAuth(user,password))
    result = appId.text
    status = appId.status_code
    if ((status >= 200) & (status <=299)):
        authToken = appId.json()
        authToken = authToken['token']
    else:
        print " "
        print "!! Error !!"  
        print "    Unable to create authorization token.  Double check that the username and password you entered."
        print "    See usage below:"
        parser.print_help()
        sys.exit()

    return authToken;

def CreateApp(authToken, switch, parser):
    global odlsBaseUrl
    # This removes any zombie apps and then calls the api to create an application
    # RETURNS: app identifier
    RemoveZombieApps(authToken, switch)

    url = odlsBaseUrl + '/applications'
    payload = {'name': 'ODL-S Demo App3 - Connected to switch: ' + switch,
                'scope': {'vnets':[switch]}}
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    appId = requests.post(url, data=json.dumps(payload), headers=headers)
    result = appId.text
    status = appId.status_code
    if ((status >= 200) & (status <=299)):
        appId = appId.json()
        appId = appId['id']
    else:
        print " "
        print "!! Error !!"  
        print "    Unable to create application.  Double check your switch identifier."
        print "    See usage below:"
        parser.print_help()
        sys.exit()

    return appId;


def CreatePolicy(authToken, appId, payload):
    global odlsBaseUrl
    # This calls the  api to create a
    # policy for the application.  
    # The policy is defined by payload which is the JSON body defining the
    #   policy to be created
    # RETURNS: policy identifier
    # NOTE: For this application, in the payload parameter, 
    #       the default policy must always be False.  If you want to see 'unmanaged endpoint'
    #       events in subscription stream then you cannot have a default policy
    #       defined.  
    #       This application depends on seeing the 'unmanaged endpoint' event.
    url = odlsBaseUrl + '/applications/' + appId + '/policies'
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}

    r = requests.post(url, data=json.dumps(payload), headers=headers)
    status = r.status_code
    if ((status >= 200) & (status <=299)):
        policyId = r.json()
        policyId = policyId['id']
    else:
        print " "
        print "!! Error !!"  
        print "    Unable to create policy."
        print r.text
        sys.exit()

    return policyId;


def CreateSubscription(authToken, appId):
    global odlsBaseUrl
    # This calls the ODL-S api to create a subscription
    # RETURNS: subscription identifier
    url = odlsBaseUrl + '/applications/' + appId + '/subscriptions'
    payload = {'type': 'httpSSE'}
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    subId = requests.post(url, data=json.dumps(payload), headers=headers)

    result = subId.text
    status = subId.status_code
    if ((status >= 200) & (status <=299)):
        subId = subId.json()
        subId = subId['id']
    else:
        print " "
        print "!! Error !!"  
        print "    Unable to create subscription to ODL-S."
        print r.text
        sys.exit()

    return subId;

def GetApps(authToken):
    global odlsBaseUrl
    url = odlsBaseUrl + '/applications'
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    r = requests.get(url, headers=headers)
    if ((r.status_code < 200) | (r.status_code > 299)):
        print "Error getting applications list: " + r.text
        sys.exit()
    else:
        return r

def GetAppInfo(authToken, appId):
    global odlsBaseUrl
    url = odlsBaseUrl + '/applications/' + appId
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    r = requests.get(url, headers=headers)
    if ((r.status_code < 200) | (r.status_code > 299)):
        print "Error getting application info: " + r.text
        sys.exit()
    else:
        return r

def GetEndpointInfo(authToken, appId, endpointId):
    global odlsBaseUrl
    url = odlsBaseUrl + '/applications/' + appId + '/endpoints/' + endpointId
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    r = requests.get(url, headers=headers)
    if ((r.status_code < 200) | (r.status_code > 299)):
        print "Error getting endpoint info: " + r.text
        sys.exit()
    else:
        return r

def DeleteEndpoint(authToken, appId, endpointId):
    global odlsBaseUrl
    url = odlsBaseUrl + '/applications/' + appId + '/endpoints/' + endpointId
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    r = requests.delete(url, headers=headers)
    if ((r.status_code < 200) | (r.status_code > 299)):
        print "Error deleting endpoint: " + r.text
        sys.exit()
    else:
        return r


def ChangeEndpointPolicy(authToken, endpointId, policyId):
    global odlsBaseUrl
    url = odlsBaseUrl + '/endpoints/' + endpointId + '/policy'
    payload = {'policy': policyId} 
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    r = requests.put(url, data=json.dumps(payload), headers=headers)
    if ((r.status_code < 200) | (r.status_code > 299)):
        print "Error changing policy for endpoint: " + r.text
        sys.exit()
    else:
        return r


def GetPolicyInfo(authToken, policyId):
    global odlsBaseUrl
    url = odlsBaseUrl + '/policies/' + policyId
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    r = requests.get(url, headers=headers)
    if ((r.status_code < 200) | (r.status_code > 299)):
        print "Error getting policy info: " + r.text
        sys.exit()
    else:
        return r

def RemoveZombieApps(authToken, switch):
    # Removes any old applications currently connected to the target switch.  Only
    # one application may be connected to a switch.
    apps = GetApps(authToken)
    for a in apps.json():
        appInfo = GetAppInfo(authToken, a['id'])
        appInfo = appInfo.json()
        appScope = appInfo['scope']
        appVnets = appScope['vnets']
        for v in appVnets:
            if (v == switch):
                print "Deleting a zombie application: " + a['id'] + ", " + a['name']
                DeleteApp(authToken,a['id'])
                break


def DeleteApp(authToken, appId):
    global odlsBaseUrl
    # This calls the  api to delete an application
    # RETURNS: app identifier
    url = odlsBaseUrl + '/applications/' + appId
    headers = {'content-type': 'application/json',
               'Authorization': 'bearer ' + authToken}
    r = requests.delete(url, headers=headers)


def GetCommandLineParser():
    # This method will process the command line parameters
    parser = argparse.ArgumentParser(description='Simple SDN Application to block/unblock devices connected to switch.')
    parser.add_argument('--id',required=True,
        help='your ODL-S Application id.  Go to sdn-developer.elbrys.com, logon, select "My Account" in top right.')
    parser.add_argument('--secret',required=True,
        help='your ODL-S Application secret. Go to sdn-developer.elbrys.com, logon, select "My Account", select "Edit Account", select the "eyeball" icon next to password.')
    parser.add_argument('--switch',required=True,
        help='the Datapath Id (DPID) for the switch connected in ODL-S dashboard without ":" e.g.  ccfa00b07b95  Go to sdn-developer.elbrys.com, logon, look in "Devices" table')
    parser.add_argument('--server',required=True, 
        help='The IP address of your ODL-S server.  Go to sdn-developer.elbrys.com, logon, look at "Controller" table.')
    parser.add_argument('--port',required=True,
        help='The TCP port number of your ODL-S server.  Go to sdn-developer.elbrys.com, logon, look at "Controller" table.')
    return parser

def UpdateEndpoints(authToken, appId, endpoints):

    # Add any new endpoints detected from ODL-S events
    while not odlsQueue.empty():
        data = odlsQueue.get()
        endpointId = data['id']
        endpointMac = data['mac']

        try:
            del endpoints[endpointId]
        except KeyError:
            pass

        endpoints[endpointId] = data

    # Go through all endpoints and update their data - data for endpoints can change over time, roaming may change
    # connected switch or IP address, policy for endpoint may habe been changed...
    for e in endpoints:
        epInfo = GetEndpointInfo(authToken, appId, e)
        if (epInfo):
            epInfo = epInfo.json()
            try:
                del endpoints[e]
            except KeyError:
                pass
            endpoints[e] = epInfo


    return endpoints

def UserCmdSelectEndpoint(endpoints):
    selectedEndpointId=""
    if not endpoints:
        print "There are currently no endpoints connected to your switch.  You may need to "
        print " cause it to generate network traffic (ping something, browse in browser, etc)."
    else:
        print "Known endpoints: "
        done = False
        while (not done):
            epList = []
            idx = 0
            for e in endpoints:
                epList.insert(idx,e) #insert e at idx - insert inserts before idx+1
                ep = endpoints.get(e)
                print "    " + str(idx) + ": " + ep['mac'] + ", " + ep['ip'] + ", " + ep['id']
                idx=idx+1
            selectedIdx = raw_input("Enter number of endpoint and enter: ")
            if ((int(selectedIdx)<0) or (int(selectedIdx)>=idx)):
                done = False
                print "The number you entered is out of range.  Please retry.  You entered: " + selectedIdx
            else:
                done = True
        print selectedIdx
        print int(selectedIdx)
        print epList
        selectedEndpointId=epList[int(selectedIdx)]
        print selectedEndpointId
    return(selectedEndpointId)

def UserCmdShowDetails(authToken, endpoints, selectedEp):
    if (len(selectedEp)<=0):
        print "    No currently selected Endpoint."
    else:
        ep = None
        ep = endpoints.get(selectedEp)
        if (not ep):
            print "    Selected endpoint no longer in endpoint list, select another. " + selectedEp
        else:
            print "    id: " + ep.get('id','No ID.')
            print "    MAC address: " + ep.get('mac','No MAC')
            print "    IP address: " + ep.get('ip','No IP address.')
            print "    Time created: " + str(ep.get('timeCreated', 'No creation time.'))
            policyId = ep.get('policy',None)
            if (not policyId):
                print "    Current policy: No Policy: unmanaged"
            else:
                pInfo = GetPolicyInfo(authToken, policyId)
                pInfo = pInfo.json()
                print "    Current policy: " + pInfo.get('name','No Name') + "(" + str(policyId) + ")"
            links = ep['links'] 
            print "    Application: " + str(links.get('application', 'No associated application.'))
            print "    Account: " + str(links.get('account', 'No associated account.'))
            print "    Connection properties: "
            properties = ep.get('properties',None)
            if (properties):
                for p in properties:
                    print "        Link type: " + p.get('type','No type') 
                    if (p['type'] == 'openflow'):
                        print "            Datapathid: " + str(p.get('datapathId','No Datapathid'))
                        print "            Port: " + str(p.get('port', 'No port'))
                    elif (p['type'] == 'tallac'):
                        print "            Vnet id: " + str(p.get('vnet', 'No vnet'))
                        print "            Vnet name: " + p.get('vnetName', 'No vnet Name.')
                        print "            NAS ID: " + str(p.get('nasId','No NAS ID defined.'))
                        print "            NAS MAC: " + p.get('nasMac', 'No MAC address')
                        print "            NAS IP: " + p.get('nasIp','No IP address')
                    else:
                        print "        <property type unknown by this app.  This app needs to be updated.>"

def UserCmdForgetEndpoint(authToken, appId, endpoints, selectedEp):
    if (len(selectedEp)<=0):
        print "    No currently selected Endpoint."
    else:
        ep = None
        ep = endpoints.get(selectedEp)
        if (not ep):
            print "    Selected endpoint no longer in endpoint list, select another. " + selectedEp
        else:
            DeleteEndpoint(authToken, appId, ep['id'])
            del endpoints[selectedEp]
    return endpoints

def UserCmdChangePolicy(authToken, appId, endpoints, selectedEp, unblockPolicyId, blockPolicyId):
    if (len(selectedEp)<=0):
        print "    No currently selected Endpoint."
    else:
        ep = None
        ep = endpoints.get(selectedEp)
        if (not ep):
            print "    Selected endpoint no longer in endpoint list, select another. " + selectedEp
        else:
            print "    Available policies: "
            print "        1. Block all traffic"
            print "        2. Allow all traffic"
            policyIdx = raw_input("Enter policy to apply and enter: ")
            if (policyIdx == "1"):
                ChangeEndpointPolicy(authToken, ep['id'], blockPolicyId)
            elif (policyIdx == "2"):
                ChangeEndpointPolicy(authToken, ep['id'], unblockPolicyId)
            else:
                print "Unknown selection. You entered: " + policyIdx

def UserCmdRestartApp(authToken, args, parser, appId, thread):
    # This will delete the current application and create a new application.
    # It returns the result from StartApplication(), see that function for its return value.
    StopApplication(authToken, appId, thread)
    appInfo = StartApplication(args, parser)
    print "    Application restarted.  All endpoints have been forgotten and will appear "
    print " as unmanaged endpoints again when they pass their first packet.  You will need "
    print " to set their policies again.  There are new identifiers for application, subscription and policies."
    return appInfo


class ReceiveOdlsEvents(threading.Thread):
    """ 
        A thread class that will receive events from ODL-S
    """
    
    def __init__ (self, authToken, subId, q):
        self.authToken = authToken
        self.subId = subId
        self.q = q
        threading.Thread.__init__ (self)
        self._stop = threading.Event()
        self._log = threading.Event()

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

    def logEnable(self):
        self._log.set()

    def logDisable(self):
        self._log.clear()

    def logToggle(self):
        if (self.logging()):
            self._log.clear()
        else:
            self._log.set()

    def logging(self):
        return self._log.isSet()
    
    def run(self):
        global odlsBaseUrl
        # This calls a subscription url as a streaming http interface.
        # It is waiting for an event message from ODL-S.
        # ODL-S sends the event message one line at a time across the stream.
        # ODL-S sends each line beginning with a '<linetype>:'.  
        # <linetype> may be 'event:' which indicates a new event, after the : is the type of event
        # <linetype> may be 'data:' which indicates json data, this will be data associated with
        #            the preceding event
        # ODL-S sends an empty line at the end of sending an event.
        # A typical event may look like (ignore the # at start...that is python comment):
        #     event: unmanagedEndPoint
        #     data: <some JSON data>
        #     data: <some more JSON data>
        #
        # This function receives each line until an empty line is sent.
        # This function collects all lines that begin with 'data:' and puts them in a buffer
        # This function parses the buffer as json
        # This function then parses the json to validate that the event was for an
        # 'unmanaged endpoint', and then gathers the event identifier 
        #  from the event.
        # RETURNS: nothing

        #Create a policy to allow all traffic

        url = odlsBaseUrl + '/httpsse/' + self.subId
        headers = {'content-type': 'application/json',
                   'Authorization': 'bearer ' + self.authToken}
        try:
            while (True):
                r = requests.get(url, headers=headers, stream=True)

                if (self.stopped()):
                    print"            -->Terminating thread that listens for ODL-S events due to stop signal from main app."
                    break

                jsonBuffer=''
                for line in r.iter_lines(chunk_size=1):
                    if (len(line) <= 0):
                        #empty line indicates end of an event report from ODL-S.
                        break
                    if line:
                        #event lines from ODL-S begin with 'event:'
                        #json lines the describe event from ODL-S begin with 'data:'
                        split = line.split(":",1)
                        if split[0] in ("data"):
                            jsonBuffer=jsonBuffer+split[1]
                        elif split[0] in ("event"):
                            if split[1] in (" keepAlive"):
                                if (self.logging()):
                                    print "                -->ODL-S event: keep alive signal (ODL-S to App connection is good)."
                            elif split[1] in (" unmanagedEndPoint"):
                                if (self.logging()):
                                    print "                -->ODL-S event: unmanaged endpoint connected, collecting its data..."
                # if we received 'data:' lines           
                if (len(jsonBuffer) > 0):
                    r = json.loads(jsonBuffer)
                    eventId = r['id']
                    typeInfo = r['type']
                    if  typeInfo in ("unmanagedEndPoint"):
                        data = r['data']
                        self.q.put(data)
                        endpointId = data['id']
                        endpointMac = data['mac']
                        if (self.logging()):
                            print "                -->ODL-S event:  unmanaged endpoint collected and added to list of endpoints: " + endpointMac
        except Exception as inst:
            print " "
            print "Exception in ODL-S Events Thread.  Terminating application." 
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to be printed directly
            print traceback.format_exc()
            os._exit(1)


def StartApplication(args, parser):
    authToken=""
    try:
        #This starts an ODL-S application.  
        #It returns:
        #  A python dictionary of the format:
        #     {'authToken':<authorization token>
        #      'appId':<application id for the new ODL-S application created>, 
        #      'unblockPolicyId':<unblock policy id>,
        #      'blockPolicyId':<policy id for block traffic policy>,
        #      'subId':<subscription id for subscription for ODL-S events>}
        #      'thread':<Thread that is listening to ODL-S events>}
        #      'selectedEp':<The key into 'endpoints' of the currently selected Endpoint...or "">}
        #      'endpoints':<The list of endpoints that have been detected by ODL-S>}
        print " "
        print "Obtaining authorization token..."
        authToken = GetAuthToken(args.id,args.secret)
        print "    ...auth token obtained: " + authToken
        print 'Creating application...'
        appId = CreateApp(authToken, args.switch,parser)
        print "    ...application created with id:" + appId 
        print " "
        print "Creating policy to allow all traffic..."
        unblockPolicyId =CreatePolicy(authToken, appId, unblockPolicyDefinition)
        print "    ...policy created with id:" + unblockPolicyId
        print " "
        print "Creating policy to block all traffic..."
        blockPolicyId =CreatePolicy(authToken, appId, blockPolicyDefinition)
        print "    ...policy created with id:" + blockPolicyId
        print " "
        print "Creating subscription to network access events..."
        subId = CreateSubscription(authToken, appId)
        print "    ...subscription created with id:" + subId
        print " "
        print "Starting thread to listen for ODL-S events on subscription..."
        odlsThread = ReceiveOdlsEvents(authToken, subId, odlsQueue)
        odlsThread.setName('ODL-S Event Listener Thread')
        odlsThread.start()
        print "    ...thread started."

        return {'authToken':authToken,
                'appId':appId, 
                'unblockPolicyId':unblockPolicyId,
                'blockPolicyId':blockPolicyId,
                'subId':subId,
                'thread':odlsThread,
                'selectedEp':"",
                'endpoints':{}}
    except Exception as inst:
        print " Exception detected while creating application..."
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to be printed directly
        print traceback.format_exc()
        if (thread):
            print "Stopping application..."
            StopApplication(authToken, appId, thread)
            print "    ...application stopped."
        elif (authToken):
            print "Deleting application..."
            DeleteApp(authToken, appId)
            print "...application deleted."

        print ""
        print "Now that the application is deleted endpoints connected to the switch will continue to have connectivity."
        print "If you go to your ODL-S dashboard (sdn-developer.elbrys.com) and refresh the screen you will "
        print " no longer see this application listed."


def StopApplication(authToken, appId, thread):
    DeleteApp(authToken, appId)
    if (thread):
        thread.stop()
        thread.join()
 
def main(): 
    global odlsBaseUrl
    # The version of the application
    #  1.0 - initial version
    version="1.0"
    print "ODL-S App3"
    print "Version: " + version
    print __doc__

    # --------------------------------
    #    Command Line Processing
    parser=GetCommandLineParser()
    args = parser.parse_args()


    odlsBaseUrl = "http://"+args.server+":"+args.port+"/ape/v1"
    print "ODL-S API is at: " + odlsBaseUrl

    # --------------------------------
    #    Main application
    try:
        appInfo = StartApplication(args,parser)

        authToken = appInfo['authToken']
        appId = appInfo['appId']
        subId = appInfo['subId']
        unblockPolicyId = appInfo['unblockPolicyId']
        blockPolicyId = appInfo['blockPolicyId']
        thread = appInfo['thread']
        selectedEp = appInfo['selectedEp']
        endpoints = appInfo['endpoints']

        thread.logDisable()

        print __doc__


        while True:
            print " "
            print " "
            print " "
            print "========================================================================="
            print "Current selected endpoint: "
            endpoints = UpdateEndpoints(authToken, appId, endpoints)
            UserCmdShowDetails(authToken, endpoints, selectedEp)
            print "-------------------------------------------------------------------------"
            print "    (s)elect an endpoint"
            print "    (d)etails of selected endpoint"
            print "    (f)orget selected endpoint"
            print "    (c)hange policy of selected endpoint"
            print "    (k)ill and restart this app"
            if (thread.logging()):
                print "    (t)oggle ODL-S event logging (currently enabled)"
            else:
                print "    (t)oggle ODL-S event logging (currently disabled)"
            print "    (h)elp"
            print "    (q)uit"
            ch = raw_input("Enter an action from above list and hit enter: ")
            print " "

            endpoints = UpdateEndpoints(authToken, appId, endpoints)
            if (ch == 's'):
                selectedEp = UserCmdSelectEndpoint(endpoints)
            elif (ch == 'd'):
                UserCmdShowDetails(authToken, endpoints, selectedEp)
            elif (ch == 'f'):
                endpoints = UserCmdForgetEndpoint(authToken, appId, endpoints, selectedEp)
            elif (ch == 'c'):
                UserCmdChangePolicy(authToken, appId, endpoints, selectedEp, unblockPolicyId, blockPolicyId)
            elif (ch == 'k'):
                appInfo = UserCmdRestartApp(authToken, args, parser, appId, thread)
                authToken = appInfo['authToken']
                appId = appInfo['appId']
                subId = appInfo['subId']
                unblockPolicyId = appInfo['unblockPolicyId']
                blockPolicyId = appInfo['blockPolicyId']
                thread = appInfo['thread']
                selectedEp = appInfo['selectedEp']
                endpoints = appInfo['endpoints']
            elif (ch == 't'):
                thread.logToggle() 
            elif (ch == 'h'):
                print __doc__
            elif (ch == 'q'):
                break
            else:
                print "Did not recognize the action you entered, please try again.  You entered: " + ch
    except Exception as inst:
        print " Exception detected while executing main loop of application..."
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to be printed directly
        print traceback.format_exc()
    finally:
        if (thread):
            print "Stopping application..."
            StopApplication(authToken, appId, thread)
            print "    ...application stopped."
        elif (authToken):
            print "Deleting application..."
            DeleteApp(authToken, appId)
            print "...application deleted."

        print ""
        print "Now that the application is deleted endpoints connected to the switch will continue to have connectivity."
        print "If you go to your ODL-S dashboard (sdn-developer.elbrys.com) and refresh the screen you will "
        print " no longer see this application listed."
    


if __name__ == "__main__": 
  # The BASE url where the ODL-S RESTful api listens
  thread = None
  odlsBaseUrl = "http://app.elbrys.com:8080/ape/v1";
  odlsQueue = Queue.Queue()
  unblockPolicyDefinition = {
               'name': 'unblocked',
               'default': False,
               'rules': [
                         {
                          'actions': [
                                        {'type': 'pass'}
                                     ]
                         }
                        ]
               }
  blockPolicyDefinition = {
               'name': 'blocked',
               'default': False,
               'rules': [
                         {
                          'actions': [
                                        {'type': 'drop'}
                                     ]
                         }
                        ]
               }             
  main()

