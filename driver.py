import socket
import SocketServer
import sys
import os
import json
from vnc_api import vnc_api
from contrail_vrouter_api.vrouter_api import ContrailVRouterApi
from pyroute2 import IPDB
from uhttplib import UnixHTTPConnection
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

MSGLEN = 4096
socket_address = '/run/docker/plugins/dockstack.sock'
socket_path = '/run/docker/plugins'
project = 'default-domain:default-project'
api_server='vip'
api_port='8082'
admin_user = 'admin'
admin_password = 'ladakh1'
tenant = 'admin'
network = '192.168.5.0/24'

class OpenContrailVN(object):
    def __init__(self, vnName):
        self.vnc_client = self.vnc_connect()
        self.vnName = vnName
        self.tenant = self.vnc_client.project_read(
                fq_name = ['default-domain', tenant])
        self.obj = vnc_api.VirtualNetwork(name = vnName,
                    parent_obj = self.tenant)

    def obj_list(self):
        list = self.vnc_client.virtual_networks_list()['virtual-networks']
        return list

    def obj_get(self):
        for item in self.obj_list():
            if (item['fq_name'][1] == self.tenant.name) and \
                    (item['fq_name'][2] == self.vnName):
                return self.vnc_client.virtual_network_read(id = item['uuid'])

    def create(self):
        try:
            self.vnc_client.virtual_network_create(self.obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def delete(self):
        obj = self.obj_get()
        try:
            print 'delete %s ' % obj.uuid
            self.vnc_client.virtual_network_delete(id = obj.uuid)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

  
        
    def vnc_connect(self):
        """open a connection to the Contrail API server"""
        self.vnc_client = vnc_api.VncApi(
            username = admin_user,
            password = admin_password,
            tenant_name = tenant,
            api_server_host=api_server,
            api_server_port=api_port)
        return self.vnc_client
class HttpResponse(object):
     def __init__(self, code, contentType, body):

         self.code = "HTTP/1.0 %s OK" % code
         if contentType == 'json':
             self.contentType = 'Content-Type: application/json'
             self.body = json.dumps(body)
         self.response = self.code + '\n'
         self.response += self.contentType + '\n\n'
         self.response += self.body + '\n'
         print self.response

class Action(object):
    def __init__(self, action, data):
        
        if action == 'Plugin.Activate':
            self.result = HttpResponse(200,'json',{ 'Implements': ['NetworkDriver','IPAM'] }).response

        if action == 'NetworkDriver.GetCapabilities':
            self.result = HttpResponse(200,'json',{ 'Scope':'global'}).response

        if action == 'IPAM.GetDefaultAddressSpaces':
            requestPool = {}
            #requestPool['addressSpace'] = '192.168.2.0/24'
            self.result = HttpResponse(200,'json',requestPool).response

        if action == 'IPAM.RequestPool':
            requestPool = {}
            requestPool['Pool'] = '192.168.2.0/24'
            self.result = HttpResponse(200,'json',requestPool).response

        if action == 'IPAM.RequestAddress':
            requestAddress = {}
            requestAddress['Address'] = '192.168.2.2/24'
            #requestAddress['Gateway'] = '192.168.2.1'
            requestAddress['PoolID']  = '1234'
            self.result = HttpResponse(200,'json',requestAddress).response

        if action == 'IPAM.ReleasePool':
            pool = {}
            pool['PoolID']  = '1234'
            self.result = HttpResponse(200,'json',pool).response

        if action == 'NetworkDriver.CreateNetwork':
            openContrailVN = OpenContrailVN(data['NetworkID']).create()
            self.result = HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.DeleteNetwork':
            openContrailVN = OpenContrailVN(data['NetworkID']).delete()
            self.result = HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.CreateEndpoint':
            interface = {}
            interface['Interface'] = {} 
            interface['Interface']['Address'] = "1.1.1.0/24"
            interface['Interface']['AddressIPv6'] = "2000::1/64"
            interface['Interface']['MacAddress'] = "de:ad:be:ef:ba:be"
            self.result = HttpResponse(200,'json',interface).response

        if action == 'NetworkDriver.DeleteEndpoint':
            endpointId = data['EndpointID']
            vethIdHost = endpointId[:8] + 'p0'
            ip = IPDB()
            with ip.interfaces[vethIdHost] as veth:
                veth.remove()
            self.result = HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.EndpointOperInfo':
            endpointInfo = {}
            endpointInfo['NetworkID'] = data['NetworkID']
            endpointInfo['EndpointID'] = data['EndpointID']
            self.result = HttpResponse(200,'json',endpointInfo).response

        if action == 'NetworkDriver.Join':
            endpointId = data['EndpointID']
            vethIdHost = endpointId[:8] + 'p0'
            vethIdContainer = endpointId[:8] + 'p1'
            ip = IPDB()
            ip.create(ifname=vethIdHost, kind='veth', peer=vethIdContainer).commit()
            with ip.interfaces[vethIdHost] as veth:
                veth.up()
            joinInfo = {}
            joinInfo['InterfaceName'] = {}
            joinInfo['InterfaceName']['SrcName'] = vethIdContainer
            joinInfo['InterfaceName']['DstPrefix'] = 'eth'
            joinInfo['Gateway'] = '1.1.1.1'
            joinInfo['GatewayIPv6'] = '2000::2'
            joinInfo['StaticRoutes'] = []
            staticRoute = {}
            staticRoute['Destination'] = '2.2.2.0/24'
            staticRoute['RouteType'] = 0
            staticRoute['NextHop'] = '1.1.1.1'
            #joinInfo['StaticRoutes'].append(staticRoute)
            self.result = HttpResponse(200,'json',joinInfo).response

        if action == 'NetworkDriver.Leave':
            self.result = HttpResponse(200,'json',{ }).response


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if format == 'html':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write("body")
        elif format == 'json':
            self.request.sendall(json.dumps({'path':self.path}))
        else:
            self.request.sendall("%s\t%s" %('path', self.path))
        return

    def do_POST(self):
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        data = json.loads(self.data_string)
        print 'self.path: %s' % self.path
        print 'data: %s' % data
        action = Action(self.path.strip('/'), data)
        result = action.result
        self.request.sendall(result)

class UnixHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        SocketServer.TCPServer.server_bind(self)
        self.server_name = "foo"
        self.server_port = 0

if __name__ == "__main__":
    print "Serving"
    if not os.path.exists(socket_path):
        os.makedirs(socket_path)
    httpd = UnixHTTPServer(socket_address, Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        os.remove(socket_address)
