#!/usr/bin/env python
import os, requests, json, sys, socket, fcntl, struct
from requests.auth import HTTPBasicAuth

zabbix_server = "192.168.56.101"
zabbix_api_admin_name = "Admin"
zabbix_api_admin_password = "zabbix"
hostname = socket.gethostname()


def post(request):
    headers = {'content-type': 'application/json'}
    return requests.post(
        "http://" + zabbix_server + "/api_jsonrpc.php",
         data=json.dumps(request),
         headers=headers,
         auth=HTTPBasicAuth(zabbix_api_admin_name, zabbix_api_admin_password)
    )

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

ip = get_ip_address('enp0s8')




auth_token = post({
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
         "user": zabbix_api_admin_name,
         "password": zabbix_api_admin_password
     },
    "auth": None,
    "id": 0}
).json()["result"]

#####################new group
def create_group():
    return post({
        "jsonrpc": "2.0",
        "method": "hostgroup.create",
        "params": {
           "name": "CloudHosts"

        },
	"auth": auth_token,
      "id": 1
   }).json()["result"]["groupids"][0]

###########################check group

def if_group():
    return post({
	"jsonrpc": "2.0",
       "method": "hostgroup.get",
         "params": {
        "output": "extend",
        "filter": {
            "name": [
                "CloudHosts"
        ]
      }
   },
	"auth": auth_token,

        "id": 1
 }).json()["result"][0]["groupid"]


try:
	if_group()
	idid = if_group()
except:
	if_group()
	idid = create_group()
       
print(idid)



  

def register_host(hostname, ip,myid):
    post({
	"jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": hostname,
            "templates": [{
                "templateid": "10001"
            }],
            "interfaces": [{
                "type": 1,
                "main": 1,
                "useip": 1,
                "ip": ip,
                "dns": "",
                "port": "10050"
            }],
            "groups": [
                {"groupid": "1"},
                {"groupid": "2"},
                {"groupid": myid}
            ]
	},
	"auth": auth_token,
        "id": 1
    })

register_host(hostname, ip, idid)

