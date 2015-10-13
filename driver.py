import socket
import SocketServer
import sys
import os
import json
import netaddr
import argparse
import yaml
from pprint import pprint
from vnc_api import vnc_api
from contrail_vrouter_api.vrouter_api import ContrailVRouterApi
from opencontrail_vrouter_netns import vrouter_control
from pyroute2 import IPDB
from uhttplib import UnixHTTPConnection
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

#socket_address = '/run/docker/plugins/dockstack.sock'
#socket_path = '/run/docker/plugins'
#project = 'default-domain:default-project'
#api_server='vip'
#api_port='8082'
#admin_user = 'admin'
#admin_password = 'ladakh1'
#tenant = 'admin'
#network = '192.168.5.0/24'

class OpenContrail(object):
    def __init__(self):
        self.vnc_client = self.vnc_connect()
        self.tenant = self.vnc_client.project_read(
                fq_name = ['default-domain', tenant])

    def vnc_connect(self):
        """open a connection to the Contrail API server"""
        self.vnc_client = vnc_api.VncApi(
            username = admin_user,
            password = admin_password,
            tenant_name = tenant,
            api_server_host=api_server,
            api_server_port=api_port)
        return self.vnc_client

class OpenContrailVirtualMachineInterface(OpenContrail):
    def __init__(self, vmName):
        super(OpenContrailVirtualMachineInterface,self).__init__()
        self._vrouter_client = ContrailVRouterApi(doconnect=True)
        self.vmName = vmName

    def getMac(self):
        interfaceName = 'veth' + self.vmName
        vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name=[self.vmName, interfaceName])
        mac = vm_interface.virtual_machine_interface_mac_addresses.mac_address[0]
        return mac

    def deleteVmi(self):
        interfaceName = 'veth' + self.vmName
        try:
            ip = self.vnc_client.instance_ip_read(fq_name_str = interfaceName)
            if ip:
                print 'deleting ip instance'
                self.vnc_client.instance_ip_delete(id=ip.uuid)
        except:
            print 'no ip instance'
        try:
            vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name=[self.vmName, interfaceName])
            if vm_interface:
                print 'deleting vm interface'
                ContrailVRouterApi().delete_port(vm_interface.uuid)
                #vrouter_control.interface_unregister(vm_interface.uuid)
                self.vnc_client.virtual_machine_interface_delete(id=vm_interface.uuid)
        except:
            print 'no vm interface'
        try:
            vm = self.vnc_client.virtual_machine_read( fq_name_str = self.vmName)
            if vm:
                print 'deleting vm'
                self.vnc_client.virtual_machine_delete(id=vm.uuid)
        except:
            print 'no vm'

    def createVmi(self, vnName, requestedIp):
        interfaceName = 'veth' + self.vmName
        try:
            ip = self.vnc_client.instance_ip_read(fq_name_str = interfaceName)
            if ip:
                print 'deleting ip instance'
                self.vnc_client.instance_ip_delete(id=ip.uuid)
        except:
            print 'no ip instance'
        try:
            vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name=[self.vmName, interfaceName])
            if vm_interface:
                print 'deleting vm interface'
                self.vnc_client.virtual_machine_interface_delete(id=vm_interface.uuid)
        except:
            print 'no vm interface'
        try:
            vm = self.vnc_client.virtual_machine_read( fq_name_str = self.vmName)
            if vm:
                print 'deleting vm'
                self.vnc_client.virtual_machine_delete(id=vm.uuid) 
        except:
            print 'no vm'
        vm_instance = vnc_api.VirtualMachine(name = self.vmName)
        self.vnc_client.virtual_machine_create(vm_instance)
        vm_interface = vnc_api.VirtualMachineInterface(name = interfaceName, parent_obj = vm_instance)
        vn = OpenContrailVN(vnName).VNget()
        vm_interface.set_virtual_network(vn)
        self.vnc_client.virtual_machine_interface_create(vm_interface)
        vm_interface = self.vnc_client.virtual_machine_interface_read(id = vm_interface.uuid)
        ip = vnc_api.InstanceIp(name = interfaceName, instance_ip_address = requestedIp.split('/')[0])
        ip.set_virtual_machine_interface(vm_interface)
        ip.set_virtual_network(vn)
        self.vnc_client.instance_ip_create(ip)
        ip = self.vnc_client.instance_ip_read(id = ip.uuid)
        ipAddress = ip.get_instance_ip_address()
        print 'ipaddress: %s' % ipAddress
        subnet = vn.network_ipam_refs[0]['attr'].ipam_subnets[0]
        gw = subnet.default_gateway
        mac = vm_interface.virtual_machine_interface_mac_addresses.mac_address[0]
        vrouterInterface = interfaceName + 'p0'
        ContrailVRouterApi().add_port(vm_instance.uuid, vm_interface.uuid, vrouterInterface, mac, display_name=vm_instance.name,
                 vm_project_id=self.tenant.uuid, port_type='NovaVMPort')
        return { 'ip': ipAddress, 'interface' : interfaceName, 'gateway' : gw , 'mac' : mac}

class OpenContrailVN(OpenContrail):
    def __init__(self, vnName):
        super(OpenContrailVN,self).__init__()
        self.vnName = vnName
        self.obj = vnc_api.VirtualNetwork(name = vnName,
                    parent_obj = self.tenant)

    def VNlist(self):
        list = self.vnc_client.virtual_networks_list()['virtual-networks']
        return list

    def VNget(self):
        for item in self.VNlist():
            if (item['fq_name'][1] == self.tenant.name) and \
                    (item['fq_name'][2] == self.vnName):
                return self.vnc_client.virtual_network_read(id = item['uuid'])

    def createNw(self, subnet, gateway=None, rtList=None):
        self.createSubnet(subnet, gateway)
        if rtList:
            rtObj = vnc_api.RouteTargetList()
            self.obj.set_route_target_list(rtObj)
            for rt in rtList:
                rtObj.add_route_target('target:%s' %(rt))
        try:
            self.vnc_client.virtual_network_create(self.obj)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def deleteNw(self):
        vnObj = self.VNget()
        try:
            print 'delete %s ' % vnObj.uuid
            self.vnc_client.virtual_network_delete(id = vnObj.uuid)
        except Exception as e:
            print 'ERROR: %s' %(str(e))

    def createSubnet(self, subnet, gateway=None):
        try:
            ipam_obj = self.vnc_client.network_ipam_read(fq_name = ['default-domain',
                                                  'default-project', 'default-network-ipam'])
        except Exception as e:
            print 'ERROR: %s' %(str(e))
            return
        cidr = subnet.split('/')
        subnet = vnc_api.SubnetType(ip_prefix = cidr[0],
                ip_prefix_len = int(cidr[1]))
        ipam_subnet = vnc_api.IpamSubnetType(subnet = subnet,
                default_gateway = gateway)
        self.obj.add_network_ipam(ref_obj = ipam_obj,
                ref_data = vnc_api.VnSubnetsType([ipam_subnet]))
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

class RequestResponse(object):
    def __init__(self):
        pass

    def execRequest(self, action, data):
        
        if action == 'Plugin.Activate':
            return HttpResponse(200,'json',{ 'Implements': ['NetworkDriver','IPAM'] }).response

        if action == 'NetworkDriver.GetCapabilities':
            return HttpResponse(200,'json',{ 'Scope':'local'}).response

        if action == 'IPAM.GetDefaultAddressSpaces':
            requestPool = {}
            return HttpResponse(200,'json',requestPool).response

        if action == 'IPAM.RequestPool':
            self.subnet = data['Pool']
            requestPool = {}
            requestPool['Pool'] = self.subnet
            return HttpResponse(200,'json',requestPool).response

        if action == 'IPAM.RequestAddress':
            plen = self.subnet.split('/')[1]
            requestAddress = {}
            if 'Address' not in data:
                reply = { 'error':'missing gateway, specify one with --gateway' }
                return HttpResponse(500,'json',reply).response
            requestAddress['Address'] = data['Address'] + '/' + plen
            return HttpResponse(200,'json',requestAddress).response

        if action == 'IPAM.ReleaseAddress':
            address = {}
            address['Address']  = data['Address']
            return HttpResponse(200,'json',address).response

        if action == 'IPAM.ReleasePool':
            pool = {}
            return HttpResponse(200,'json',pool).response

        if action == 'NetworkDriver.CreateNetwork':
            subnet  = data['IPv4Data'][0]['Pool']
            gateway = data['IPv4Data'][0]['Gateway'].split('/')[0]
            rtList = []
            if 'rt' in data['Options']['com.docker.network.generic']:
                rt = data['Options']['com.docker.network.generic']['rt']
                rtList = rt.split(',')
            openContrailVN = OpenContrailVN(data['NetworkID']).createNw(subnet, gateway, rtList)
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.DeleteNetwork':
            openContrailVN = OpenContrailVN(data['NetworkID']).deleteNw()
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.CreateEndpoint':
            networkId = data['NetworkID']
            endpointId = data['EndpointID']
            hostId = endpointId[:8]
            ipAddress = data['Interface']['Address']
            result  = OpenContrailVirtualMachineInterface(hostId).createVmi(networkId, ipAddress)
            interface = {}
            interface['Interface'] = {} 
            interface['Interface']['MacAddress'] = result['mac']
            return HttpResponse(200,'json',interface).response

        if action == 'NetworkDriver.DeleteEndpoint':
            endpointId = data['EndpointID']
            hostId = endpointId[:8]
            OpenContrailVirtualMachineInterface(hostId).deleteVmi()
            endpointId = data['EndpointID']
            vethIdHost = 'veth' + endpointId[:8] + 'p0'
            ip = IPDB()
            with ip.interfaces[vethIdHost] as veth:
                veth.remove()
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.EndpointOperInfo':
            endpointInfo = {}
            endpointInfo['NetworkID'] = data['NetworkID']
            endpointInfo['EndpointID'] = data['EndpointID']
            return HttpResponse(200,'json',endpointInfo).response

        if action == 'NetworkDriver.Join':
            endpointId = data['EndpointID']
            hostId = endpointId[:8]
            networkId = data['NetworkID']
            vethIdHost = 'veth' + endpointId[:8] + 'p0'
            vethIdContainer = 'veth' + endpointId[:8]
            vn = OpenContrailVN(networkId).VNget()
            subnet = vn.network_ipam_refs[0]['attr'].ipam_subnets[0]
            gateway = subnet.default_gateway
            mac = OpenContrailVirtualMachineInterface(hostId).getMac()
            ip = IPDB()
            ip.create(ifname=vethIdHost, kind='veth', peer=vethIdContainer).commit()
            with ip.interfaces[vethIdHost] as veth:
                veth.up()
            with ip.interfaces[vethIdContainer] as veth:
                veth.address = mac
            joinInfo = {}
            joinInfo['InterfaceName'] = {}
            joinInfo['InterfaceName']['SrcName'] = vethIdContainer
            joinInfo['InterfaceName']['DstPrefix'] = 'eth'
            joinInfo['Gateway'] = gateway
            #joinInfo['GatewayIPv6'] = '2000::2'
            joinInfo['StaticRoutes'] = []
            #staticRoute = {}
            #staticRoute['Destination'] = '2.2.2.0/24'
            #staticRoute['RouteType'] = 0
            #staticRoute['NextHop'] = '1.1.1.1'
            #joinInfo['StaticRoutes'].append(staticRoute)
            return HttpResponse(200,'json',joinInfo).response

        if action == 'NetworkDriver.Leave':
            return HttpResponse(200,'json',{ }).response


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
        result = requestResponse.execRequest(self.path.strip('/'), data)
        self.request.sendall(result)

class UnixHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        SocketServer.TCPServer.server_bind(self)
        self.server_name = "foo"
        self.server_port = 0

parser = argparse.ArgumentParser(description='OpenContrail Docker Libnetwork Driver')
parser.add_argument('-f','--file',
                   help='Path to Contrail API Server configuration file')
parser.add_argument('-u','--admin_user',
                   help='Admin user for Contrail API Server')
parser.add_argument('-t','--admin_tenant',
                   help='Admin tenant for Contrail API Server')
parser.add_argument('-p','--admin_password',
                   help='Admin password for Contrail API Server')
parser.add_argument('-a','--api_server',
                   help='Contrail API Server IP/FQDN')
parser.add_argument('-x','--api_port',default='8082',
                   help='Contrail API Server port')
parser.add_argument('-y','--tenant',
                   help='Project')
parser.add_argument('-s','--socketpath',default='/run/docker/plugins',
                   help='Project')

args = parser.parse_args()
admin_user=''
tenant=''
admin_password=''
api_server=''
api_port=''
socket_path=''

if args.file:
    f = open(args.file,'r')
    configFile = f.read().strip()
    configYaml = yaml.load(configFile)
    pprint(configYaml)
    api_server = configYaml['api_server']
    api_port = configYaml['api_port']
    admin_user = configYaml['admin_user']
    admin_password = configYaml['admin_password']
    tenant = configYaml['admin_tenant']
    socket_path = configYaml['socketpath']

if args.admin_user:
    admin_user = args.admin_user

if args.admin_tenant:
    tenant = args.admin_tenant

if args.admin_password:
    admin_password = args.admin_password

if args.api_server:
    api_server = args.api_server

if args.api_port:
    api_port = args.api_port

if args.socketpath:
    socket_path = args.socketpath

if (not admin_user or not tenant 
                  or not admin_password
                  or not api_server
                  or not api_port
                  or not socket_path):
   print args.admin_user
   print args.admin_tenant
   print args.admin_password
   print args.api_server
   print args.api_port
   print args.socketpath
   print parser.print_help()
   sys.exit()

socket_address = socket_path + '/dockstack.sock'
print socket_address
#sys.exit()

if __name__ == "__main__":
    print "Serving"
    requestResponse = RequestResponse()
    if not os.path.exists(socket_path):
        os.makedirs(socket_path)
    httpd = UnixHTTPServer(socket_address, Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        os.remove(socket_address)
