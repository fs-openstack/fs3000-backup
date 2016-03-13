#!/usr/bin/python
# Copyright (c) 2015 - 2016 Fortunet Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#    Depends on: python-nova: 1:2014.2.4-0ubuntu1~cloud4; lsscsi: 0.27-2

# For user area
STORAGE_MASTER_IP = '172.16.240.25'
STORAGE_SLAVE_IP = '172.16.240.27'
STORAGE_USERNAME = 'admin'
STORAGE_PASSWORD = ''

"""
Drivers for Frotunet FS3000 array based on RESTful API.
"""
import cookielib
import json
import random
import re
import types
import urllib2
import subprocess
import sys
import time
import struct
from nova.virt.libvirt import utils as libvirt_utils
from nova.storage import linuxscsi
from nova.virt.disk.mount import nbd
from time import gmtime, strftime

HTTP_DEBUG=0
CMD_DEBUG=0
VERSION = '00.00.01'
GiB = 1024 * 1024 * 1024
ENABLE_TRACE = False
PROTOCOL='FC'
RBD_PROTO_HDR_SIZE=12
RBD_PROTO_HDR="rbd diff v1\n"

def decorate_all_methods(method_decorator):
    """Applies decorator on the methods of a class.

    This is a class decorator, which will apply method decorator referred
    by method_decorator to all the public methods (without underscore as
    the prefix) in a class.
    """
    if not ENABLE_TRACE:
        return lambda cls: cls

    def _decorate_all_methods(cls):
        for attr_name, attr_val in cls.__dict__.items():
            if (isinstance(attr_val, types.FunctionType) and
                    not attr_name.startswith("_")):
                setattr(cls, attr_name, method_decorator(attr_val))
        return cls

    return _decorate_all_methods


def log_enter_exit(func):
    if not 'True':
        return func

    def inner(self, *args, **kwargs):
        print("Entering %(cls)s.%(method)s",
                  {'cls': self.__class__.__name__,
                   'method': func.__name__})
        #start = timeutils.utcnow()
        ret = func(self, *args, **kwargs)
        #end = timeutils.utcnow()
        print("Exiting %(cls)s.%(method)s. "
                  "Spent %(duration)s sec. "
                  "Return %(return)s",
                  {'cls': self.__class__.__name__,
                   #'duration': timeutils.delta_seconds(start, end),
                   'method': func.__name__,
                   'return': ret})
        return ret
    return inner


@decorate_all_methods(log_enter_exit)
class CCFS3000RESTClient(object):
    """Fortunet FS3000 Client interface handing REST calls and responses."""

    HEADERS = {'Accept': 'application/json',
               'Content-Type': 'application/json'}
    HostTypeEnum_HostManual = 1
    HostLUNTypeEnum_LUN = 1
    HostLUNAccessEnum_NoAccess = 0
    HostLUNAccessEnum_Production = 1

    def __init__(self, master_ip, slave_ip, port=443, user='', password='', debug=False):
        self.username = user
        self.password = password
        self.active_storage_ip = master_ip
        self.slave_storage_ip = slave_ip
        self.port = port
        if (debug): print('init active storate ip %s, slave storage ip %s' % (master_ip, slave_ip))
        self.mgmt_url = 'https://%(host)s:%(port)s' % {'host': master_ip,
                                                       'port': port}
        self.debug = debug
        self.cookie_jar = cookielib.CookieJar()
        self.cookie_handler = urllib2.HTTPCookieProcessor(self.cookie_jar)
        self.url_opener = urllib2.build_opener(self.cookie_handler)

    def get_active_storage_ip (self):
        return self.active_storage_ip

    def get_slave_storage_ip (self):
        return self.slave_storage_ip

    def set_slave_storage_ip (self, slave_ip):
        if self.slave_storage_ip != slave_ip:
            if (self.debug): print('set slave storage ip %s' % slave_ip)
        self.slave_storage_ip = slave_ip

    def _http_log_req(self, req):
        if not self.debug:
            return

        string_parts = ['curl -i']
        string_parts.append(' -X %s' % req.get_method())

        for k in req.headers:
            header = ' -H "%s: %s"' % (k, req.headers[k])
            string_parts.append(header)

        if req.data:
            string_parts.append(" -d '%s'" % (req.data))
        string_parts.append(' ' + req.get_full_url())
        print("\nREQ: %s\n", "".join(string_parts))

    def _http_log_resp(self, resp, body, failed_req=None):
        if not self.debug and failed_req is None:
            return
        if failed_req:
            if (self.debug): print(
                _LE('REQ: [%(method)s] %(url)s %(req_hdrs)s\n'
                    'REQ BODY: %(req_b)s\n'
                    'RESP: [%(code)s] %(resp_hdrs)s\n'
                    'RESP BODY: %(resp_b)s\n'),
                {'method': failed_req.get_method(),
                 'url': failed_req.get_full_url(),
                 'req_hdrs': failed_req.headers,
                 'req_b': failed_req.data,
                 'code': resp.getcode(),
                 'resp_hdrs': str(resp.headers).replace('\n', '\\n'),
                 'resp_b': body})
        else:
            print(
                "RESP: [%s] %s\nRESP BODY: %s\n",
                resp.getcode(),
                str(resp.headers).replace('\n', '\\n'),
                body)

    def _http_log_err(self, err, req):
        if (self.debug): print(
            _LE('REQ: [%(method)s] %(url)s %(req_hdrs)s\n'
                'REQ BODY: %(req_b)s\n'
                'ERROR CODE: [%(code)s] \n'
                'ERROR REASON: %(resp_e)s\n'),
            {'method': req.get_method(),
             'url': req.get_full_url(),
             'req_hdrs': req.headers,
             'req_b': req.data,
             'code': err.code,
             'resp_e': err.reason})

    def _getRelURL(self, parameter):
        strPara = ""
        for key, value in parameter.items() :
            strPara += "&%(key)s=%(value)s" % {'key' : key, 'value' : value}
        strURL = "/serviceHandler.php?" + strPara
        if self.debug:
            print("_getRelURL = %s" % strURL)
        return strURL

    def _request(self, rel_url, req_data=None, method=None,
                 return_rest_err=True, assign_url=None):
        req_body = None if req_data is None else json.dumps(req_data)
        err = None
        resp_data = None
        url = self.mgmt_url + rel_url if not assign_url else assign_url + rel_url
        req = urllib2.Request(url, req_body, CCFS3000RESTClient.HEADERS)
        if method not in (None, 'GET', 'POST'):
            req.get_method = lambda: method
        self._http_log_req(req)
        try:
            resp = self.url_opener.open(req)
            resp_body = resp.read()
            resp_data = json.loads(resp_body) if resp_body else None
            self._http_log_resp(resp, resp_body)
        except urllib2.HTTPError as http_err:
            if hasattr(http_err, 'read'):
                resp_body = http_err.read()
                self._http_log_resp(http_err, resp_body, req)
                if resp_body:
                    resp_json = json.loads(resp_body)
                    err = {'errorCode': resp_json['code'],
                           'httpStatusCode': http_err.code,
                           'messages': resp_json['description'],
                           'request': req}
                else:
                    err = {'errorCode': -1,
                           'httpStatusCode': http_err.code,
                           'messages': six.text_type(http_err),
                           'request': req}
            else:
                self._http_log_err(http_err, req)
                resp_data = http_err.reason
                err = {'errorCode': -1,
                       'httpStatusCode': http_err.code,
                       'messages': six.text_type(http_err),
                       'request': req}
        except Exception as ex:
            if (self.debug): print('_request: Exception %s' % ex)
            err = ex
        finally:
            if not return_rest_err:
                raise exception.VolumeBackendAPIException(data=err)
            return (err, resp_data) if return_rest_err else resp_data

    def _login(self, assign_url=None):
        url_parameter = {'service' : 'LoginService',
                         'action' : 'login',
                         'account' : self.username,
                         'password' : self.password}
        login_rel = self._getRelURL(url_parameter)
        err, resp = self._request(login_rel, assign_url=assign_url)

        if not err:
            php_session_id = None
            for cookie in self.cookie_jar:
                if cookie.name == "PHPSESSID":
                    php_session_id = cookie.value
                    break
            cookie_content = 'PHPSESSID=%s'%php_session_id
            self.url_opener.addheaders.append(('Cookie', cookie_content))
        return err, resp

    def _is_login(self):
        url_parameter = {'service' : 'LoginService',
                         'action' : 'echoIsLogin'}
        return self._request(self._getRelURL(url_parameter))

    def _logout(self):
        url_parameter = {'service' : 'LoginService',
                         'action' : 'logout'}
        self._request(self._getRelURL(url_parameter))

    def request_ha (req):
        def ha_inner(self, *args, **kwargs):
            err, resp = req(self, *args, **kwargs)
            if err and self.slave_storage_ip:
                print('request ha: try slave storage')
                try_ha_url = 'https://%(host)s:%(port)s' % {'host': self.slave_storage_ip,
                                                            'port': self.port}
                try_login_err, try_login_resp = self._login(assign_url=try_ha_url)
                if not try_login_err:
                    if 'permission' in try_login_resp:
                        if (self.debug): print('request ha: active storage ip change to %s' % self.slave_storage_ip)
                        self.active_storage_ip, self.slave_storage_ip = self.slave_storage_ip, self.active_storage_ip
                        self.mgmt_url = try_ha_url
                        url_para = args[0]
                        rel_url = self._getRelURL(url_para)
                        err, resp = self._request(rel_url)
                    elif 'code' in try_login_resp:
                        if (self.debug): print('request ha: login with err %s' % try_loginresp['code'])
            return err, resp
        return ha_inner

    @request_ha
    def request (self, url_para):
        err, resp = self._is_login()
        if err:
            if (self.debug): print('request: check is login failed.')
            return err, resp
        elif 'login' in resp:
            if resp['login']=='false':
                err, resp = self._login()
                if err:
                    if (self.debug): print('request: login failed.')
                    return err, resp
                elif 'code' in resp:
                    if (self.debug): print('request: login with err %s' % resp['code'])
                    return err, resp
        else:
            if (self.debug): print('request: check is login resp without login parameter')
            return err, resp

        rel_url = self._getRelURL(url_para)
        err, resp = self._request(rel_url)
        #self._logout()
        return err, resp

    def get_pools(self, fields=None):
        url_parameter = {'service' : 'VgService',
                         'action' : 'getAllVGs'}
        err, pools = self.request(url_parameter)
        return pools if not err else None

    def get_luns(self):
        url_parameter = {'service' : 'LvService',
                         'action' : 'getAllLVs'}
        return self.request(url_parameter)

    def get_all_type_of_luns(self):
        url_parameter = {'service' : 'LvService',
                         'action' : 'getAllTypeOfVolumes'}
        return self.request(url_parameter)

    def get_thin_dump_diff(self, from_snap, to_snap):
        url_parameter = {'service' : 'LvService',
                         'action' : 'thinDumpDiff',
                         'from' : from_snap,
                         'to' : to_snap}
        return self.request(url_parameter)

    def get_lun_by_name(self, name):
        err, luns = self.get_all_type_of_luns()
        if not err:
            for lun in luns :
                if (lun['Type'] == 'thin Volume' and
                    lun['Name'] == name):
                    return err, lun
        return err, None

    def get_lun_by_id(self, lun_id):
        err, luns = self.get_all_type_of_luns()
        if not err:
            for lun in luns :
                if lun['Id'] == lun_id:
                    return err, lun
        return err, None

    def get_snaps_by_lunid(self, lun_id):
        url_parameter = {'service' : 'LvService',
                         'action' : 'getSnapshotsByLv',
                         'lvId' : lun_id}
        return self.request(url_parameter)

    def get_snap_by_name (self, lun_id, snapname):
        err, snaps = self.get_snaps_by_lunid(lun_id)
        if not err:
            for snap in snaps :
                if snap['Name'] == snapname:
                    return err, snap
        return err, None

    def get_system_info(self):
        url_parameter = {'service' : 'SysinfoService',
                         'action' : 'getDetail'}
        err, resp = self.request(url_parameter)
        return None if err else resp
    def get_active_fc_wwns(self, initiator):
        url_parameter = {'service' : 'FCLunMappingService',
                         'action' : 'getTargetPortNumberByInitator',
                         'wwn' : initiator}
        err, resp = self.request(url_parameter)
        return resp

    def create_lun(self, pool_id, name, size, lvtype):
        url_para = {'service' : 'LvService',
                    'action' : 'createLv',
                    'name' : name,
                    'vgId' : pool_id,
                    'sizeGB' : size,
                    'lvType' : lvtype}
        err, resp = self.request(url_para)
        return (err, None) if err else \
            (err, resp)

    def delete_lun(self, lun_id, force_snap_deletion=False):
        url_para = {'service' : 'LvService',
                    'action' : 'deleteLv',
                    'id' : lun_id}
        return self.request(url_para)

    def create_host(self, hostname):
        host_create_url = '/api/types/host/instances'
        data = {'type': CCFS3000RESTClient.HostTypeEnum_HostManual,
                'name': hostname}
        err, resp = self._request(host_create_url, data)
        return (err, None) if err else (err, resp['content'])

    def delete_host(self, host_id):
        host_delete_url = '/api/instances/host/%s' % host_id
        err, resp = self._request(host_delete_url, None, 'DELETE')
        return err, resp

    def create_initiator(self, initiator_uid, host_id):
        initiator_create_url = '/api/types/hostInitiator/instances'
        data = {'host': {'id': host_id},
                'initiatorType': 2 if initiator_uid.lower().find('iqn') == 0
                else 1,
                'initiatorWWNorIqn': initiator_uid}
        err, resp = self._request(initiator_create_url, data)
        return (err, None) if err else (err, resp['content'])

    def register_initiator(self, initiator_id, host_id):
        initiator_register_url = \
            '/api/instances/hostInitiator/%s/action/register' % initiator_id
        data = {'host': {'id': host_id}}
        err, resp = self._request(initiator_register_url, data)
        return err, resp

    def get_host_lun_by_ends(self, host_id, lun_id,
                             protocol):
        if protocol == 'FC':
            url_para = {'service' : 'FCLunMappingService',
                        'action' : 'getAllFCLunMappings'}
        elif protocol == 'iSCSI':
            url_para = {'service' : 'LunMappingService',
                        'action' : 'getAllFS3000LunMappings'}
        err, resp = self.request(url_para)

        #print("lun map %s", resp)
        for mapping in resp:
            if (mapping['lvId'] == lun_id):
                return mapping['lunNumber']

    def _get_avail_host_lun(self, protocol, initiator):
        if protocol == 'FC':
            url_para = {'service' : 'FCLunMappingService',
                        'action' : 'echoUsedLunsByWWN',
                        'wwn' : initiator.upper()}
        elif protocol == 'iSCSI':
            url_para = {'service' : 'LunMappingService',
                        'action' : 'echoUsedLunsByInitiator',
                        'initiator' : initiator}
        else:
            msg = ('storage_protocol %(invalid)s is not supported. '
                    ) % {'invalid': protocol}
            if (self.debug): print(msg)
            raise exception.VolumeBackendAPIException(data=msg)

        err, resp = self.request(url_para)

        host_lun = 0
        resp.sort()
        for used_lun in resp:
            if (host_lun == int(used_lun)):
                host_lun += 1

        if (CMD_DEBUG == 1):
            print("take host_lun %s, used_lun %s" % (host_lun, resp))
        return host_lun

    def expose_lun(self, lun_id, initiators, protocol):
        for initiator in initiators:
            host_lun = self._get_avail_host_lun(protocol, initiator)
            if (CMD_DEBUG == 1):
                 print("expose_lun lun_id %s init %s host_lun %s" %
                    (lun_id, initiator, host_lun))
            if protocol == 'FC':
                url_para = {'service' : 'FCLunMappingService',
                            'action' : 'createFCLunMapping',
                            'lvId' : lun_id,
                            'lunNumber' : host_lun,
                            'wwn' : initiator.upper()}
            elif protocol == 'iSCSI':
                url_para = {'service' : 'LunMappingService',
                            'action' : 'createLunMappingWithChapUser',
                            'lvId' : lun_id,
                            'lunNumber' : host_lun,
                            'initiator' : initiator}
            else:
                msg = ('storage_protocol %(invalid)s is not supported. '
                        ) % {'invalid': protocol}
                if (self.debug): print(msg)
                raise exception.VolumeBackendAPIException(data=msg)
            err, resp = self.request(url_para)
        return err, resp

    def hide_lun(self, lun_id, host_id, protocol):
        if (CMD_DEBUG == 1):
            print("hide_lun lun_id %s, host_id %s, proto %s" %
                (lun_id, host_id, protocol))
        host_lun = self.get_host_lun_by_ends(host_id, lun_id, protocol)
        if protocol == 'FC':
            url_para = {'service' : 'FCLunMappingService',
                        'action' : 'deleteFCLunMapping',
                        'lunNumber' : host_lun,
                        'wwn' : host_id}
        elif protocol == 'iSCSI':
            url_para = {'service' : 'LunMappingService',
                        'action' : 'deleteLunMappingWithChapUser',
                        'lunNumber' : host_lun,
                        'initiator' : host_id}
        err, resp = self.request(url_para)
        return err,resp

    def create_snap(self, lun_id, snap_name, lun_size, snap_description=None):
        url_para = {'service' : 'LvService',
                    'action' : 'createSnapshot',
                    'lvId' : lun_id,
                    'name' : snap_name,
                    'spaceGB' : lun_size}
        return self.request(url_para)

    def delete_snap(self, snap_id):
        """Deletes the snap by the snap_id."""
        url_para = {'service' : 'LvService',
                    'action' : 'deleteSnapshot',
                    'snapshotId' : snap_id}
        return self.request(url_para)

    def create_lun_from_snap (self, name, snap_id):
        url_para = {'service' : 'LvService',
                    'action' : 'createLvFromSnapshot',
                    'name' : name,
                    'snapshotId' : snap_id}
        return self.request(url_para)

    def is_flatten_lun (self, lun_id):
        url_para = {'service' : 'LvService',
                    'action' : 'isFlattenLv',
                    'lvId' : lun_id}
        return self.request(url_para)

    def flatten_lun (self, lun_id):
        url_para = {'service' : 'LvService',
                    'action' : 'flattenLv',
                    'lvId' : lun_id}
        return self.request(url_para)

    def get_lun_or_snap_size (self, lun_or_snap_id):
        url_para = {'service' : 'LvService',
                    'action' : 'getLvRSize',
                    'lvId' : lun_or_snap_id}
        return self.request(url_para)

    def rollback_to_snap (self, snap_id):
        url_para = {'service' : 'LvService',
                    'action' : 'doRollbackToSnapshot',
                    'SnapId' : snap_id}
        return self.request(url_para)

    def extend_lun(self, lun_id, size):
        url_para = {'service' : 'LvService',
                    'action' : 'doExpandLvSize',
                    'lvId' : lun_id,
                    'expandedSizeMB' : size*1024}
        err, resp = self.request(url_para)
        return (err, None) if err else \
            (err, resp)

    def modify_lun_name(self, lun_id, new_name):
        """Modify the lun name."""
        lun_modify_url = \
            '/api/instances/storageResource/%s/action/modifyLun' % lun_id
        data = {'name': new_name}
        err, resp = self._request(lun_modify_url, data)
        if err:
            if err['errorCode'] in (0x6701020,):
                if (self.debug): print(_LW('Nothing to modify, the lun %(lun)s '
                                'already has the name %(name)s.'),
                            {'lun': lun_id, 'name': new_name})
            else:
                reason = (_('Manage existing lun failed. Can not '
                          'rename the lun %(lun)s to %(name)s') %
                          {'lun': lun_id, 'name': new_name})
                raise exception.VolumeBackendAPIException(
                    data=reason)

@decorate_all_methods(log_enter_exit)
class CCFS3000Helper(object):

    stats = {'driver_version': VERSION,
             'storage_protocol': None,
             'free_capacity_gb': 'unknown',
             'reserved_percentage': 0,
             'total_capacity_gb': 'unknown',
             'vendor_name': 'Fortunet',
             'volume_backend_name': None}

    def __init__(self, protocol, debug=False):
        self.storage_protocol = protocol
        self.supported_storage_protocols = ('iSCSI', 'FC')
        self.lvtype = 4 #thin lv
        if self.storage_protocol not in self.supported_storage_protocols:
            msg = ('storage_protocol %(invalid)s is not supported. '
                    'The valid one should be among %(valid)s.') % {
                'invalid': self.storage_protocol,
                'valid': self.supported_storage_protocols}
            if (self.debug): print(msg)
            raise exception.VolumeBackendAPIException(data=msg)
        self.config_master_ip = STORAGE_MASTER_IP
        self.config_slave_ip = STORAGE_SLAVE_IP
        self.storage_username = STORAGE_USERNAME
        self.storage_password = STORAGE_PASSWORD
        self.debug = debug
        if (len(libvirt_utils.get_fc_wwpns()) == 0):
            raise NameError("Error, plz check FC link")
        wwpn = []
        wwpn.append(libvirt_utils.get_fc_wwpns().pop().upper())
        iscsi_initiator = []
        iscsi_initiator.append(libvirt_utils.get_iscsi_initiator())
        self.connector = {'initiator': iscsi_initiator,
                          'wwpns': wwpn}
        if (CMD_DEBUG >= 2):
            print "connector, ", self.connector
        #self.max_over_subscription_ratio = (
        #    self.configuration.max_over_subscription_ratio)
        # self.lookup_service_instance = None
        # Here we use group config to keep same as cinder manager
        #zm_conf = Configuration(manager.volume_manager_opts)
        #if (zm_conf.safe_get('zoning_mode') == 'fabric' or
        #        self.configuration.safe_get('zoning_mode') == 'fabric'):
        #    from cinder.zonemanager.fc_san_lookup_service \
        #        import FCSanLookupService
        #    self.lookup_service_instance = \
        #        FCSanLookupService(configuration=self.configuration)
        self.client = CCFS3000RESTClient(self.config_master_ip,
                                         self.config_slave_ip,
                                         443,
                                         self.storage_username,
                                         self.storage_password,
                                         debug)
        system_info = self.client.get_system_info()
        if not system_info:
            msg = ('Basic system information is unavailable.')
            if (self.debug): print(msg)
            raise NameError(msg)
        self.storage_serial_number = system_info['serialNumber']

        if self.config_slave_ip:
            self.is_update_slave_ip = False
        else:
            self.is_update_slave_ip = True
            if system_info['controllerHAMode'] == 'DUAL':
                self.client.set_slave_storage_ip(system_info['slaveIp'])

        conf_pools = ""
        # When managed_all_pools is True, the storage_pools_map will be
        # updated in update_volume_stats.
        self.is_managing_all_pools = False if conf_pools else True
        #self.storage_pools_map = self._get_managed_storage_pools_map(
        #    conf_pools)
        #self.thin_enabled = False
        #self.storage_targets = self._get_storage_targets()

    def _get_managed_storage_pools_map(self, pools):
        managed_pools = self.client.get_pools()
        if pools:
            storage_pool_names = set([po.strip() for po in pools.split(",")])
            array_pool_names = set([po['Name'] for po in managed_pools])
            non_exist_pool_names = storage_pool_names.difference(
                array_pool_names)
            storage_pool_names.difference_update(non_exist_pool_names)
            if not storage_pool_names:
                msg = ("All the specified storage pools to be managed "
                        "do not exist. Please check your configuration. "
                        "Non-existent "
                        "pools: %s") % ",".join(non_exist_pool_names)
                raise exception.VolumeBackendAPIException(data=msg)
            if non_exist_pool_names:
                if (self.debug): print(_LW("The following specified storage pools "
                                "do not exist: %(unexist)s. "
                                "This host will only manage the storage "
                                "pools: %(exist)s"),
                            {'unexist': ",".join(non_exist_pool_names),
                             'exist': ",".join(storage_pool_names)})
            else:
                print("This host will manage the storage pools: %s.",
                          ",".join(storage_pool_names))

            managed_pools = filter(lambda po: po['Name'] in storage_pool_names,
                                   managed_pools)
        else:
            print("No storage pool is configured. This host will "
                      "manage all the pools on the FS3000 system.")

        return self._build_storage_pool_id_map(managed_pools)

    def _build_storage_pool_id_map(self, pools):
        return {po['Name']: po['Id'] for po in pools}

    def update_slave_storage_ip(self):
        if not self.is_update_slave_ip:
            return

        sys_info = self.client.get_system_info()
        if not sys_info:
            if (self.debug): print(_LW('update secondary storage ip: can not get sysinfo'))
            return

        slave_ip = None
        if sys_info['controllerHAMode'] == 'DUAL':
            slave_ip = sys_info['slaveIp']
        self.client.set_slave_storage_ip(slave_ip)
        print("Updated slave storage ip %s" % slave_ip)
        return

    def _get_iscsi_targets(self):
        res = {'a': [], 'b': []}
        node_dict = {}
        for node in self.client.get_iscsi_nodes(('id', 'name')):
            node_dict[node['id']] = node['name']
        fields = ('id', 'ipAddress', 'ethernetPort', 'iscsiNode')
        pat = re.compile(r'sp(a|b)', flags=re.IGNORECASE)
        for portal in self.client.get_iscsi_portals(fields):
            eth_id = portal['ethernetPort']['id']
            node_id = portal['iscsiNode']['id']
            m = pat.match(eth_id)
            if m:
                sp = m.group(1).lower()
                item = (node_dict[node_id], portal['ipAddress'],
                        portal['id'])
                res[sp].append(item)
            else:
                if (self.debug): print(_LW('SP of %s is unknown'), portal['id'])
        return res

    def _get_fc_targets(self):
        res = {'a': [], 'b': []}
        fields = ('id', 'wwn', 'storageProcessorId')
        pat = re.compile(r'sp(a|b)', flags=re.IGNORECASE)
        for port in self.client.get_fc_ports(fields):
            sp_id = port['storageProcessorId']['id']
            m = pat.match(sp_id)
            if m:
                sp = m.group(1).lower()
                wwn = port['wwn'].replace(':', '')
                node_wwn = wwn[0:16]
                port_wwn = wwn[16:32]
                item = (node_wwn, port_wwn, port['id'])
                res[sp].append(item)
            else:
                if (self.debug): print(_LW('SP of %s is unknown'), port['id'])
        return res

    def _get_storage_targets(self, connector):
        if self.storage_protocol == 'iSCSI':
            return self._get_iscsi_targets(connector)
        elif self.storage_protocol == 'FC':
            return self._get_fc_targets(connector)
        else:
            return {'a': [], 'b': []}

    def _get_volumetype_extraspecs(self, volume):
        specs = {}

        type_id = volume['volume_type_id']
        if type_id is not None:
            specs = volume_types.get_volume_type_extra_specs(type_id)

        return specs

    def _load_provider_location(self, provider_location):
        pl_dict = {}
        for item in provider_location.split('|'):
            k_v = item.split('^')
            if len(k_v) == 2 and k_v[0]:
                pl_dict[k_v[0]] = k_v[1]
        return pl_dict

    def _dumps_provider_location(self, pl_dict):
        return '|'.join([k + '^' + pl_dict[k] for k in pl_dict])

    def get_lun_by_id(self, lun_id):
        err, lun = self.client.get_lun_by_id(lun_id)
        if err or not lun:
            raise exception.VolumeBackendAPIException(
                "Cannot find lun with id : %s" % lun_id)
        return lun

    def _get_target_storage_pool_name(self, volume):
        return vol_utils.extract_host(volume['host'], 'pool')

    def _get_target_storage_pool_id(self, volume):
        name = self._get_target_storage_pool_name(volume)
        return self.storage_pools_map[name]

    def _api_exec_success (self, resp):
        return True if resp['code'] == 0 else False

    def create_volume(self, volume):
        name = str(volume['display_name'])+'-'+str(volume['name'])
        size = volume['size']
        err, resp = self.client.create_lun(
            self._get_target_storage_pool_id(volume), name, size,
            self.lvtype)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'create volume %s failed with err %s.' % (volume['name'], resp['code'])
            raise exception.VolumeBackendAPIException(data=err_msg)

        err, lun = self.client.get_lun_by_name(name)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not lun:
            err_msg = 'can not get created LV by name %s' % name
            raise exception.VolumeBackendAPIException(data=err_msg)

        pl_dict = {'system': self.storage_serial_number,
                   'type': 'lun',
                   'id': lun['Id']}
        model_update = {'provider_location':
                        self._dumps_provider_location(pl_dict)}
        volume['provider_location'] = model_update['provider_location']
        return model_update

    def create_volume_from_snapshot(self, volume, snapshot):
        name = volume['display_name']+'-'+volume['name']
        snap_id = self._extra_lun_or_snap_id(snapshot)
        if not snap_id: #TODO: add log message
            return
        err, resp = self.client.create_lun_from_snap(name, snap_id)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'create volume %s from snapshot %s/%s failed with err %s.' % (volume['name'], snapshot['name'], snap_id, resp['code'])
            raise exception.VolumeBackendAPIException(data=err_msg)

        err, lun = self.client.get_lun_by_name(name)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not lun:
            err_msg = 'can not get created LV by name %s' % name
            raise exception.VolumeBackendAPIException(data=err_msg)

        pl_dict = {'system': self.storage_serial_number,
                   'type': 'lun',
                   'id': lun['Id']}
        model_update = {'provider_location':
                        self._dumps_provider_location(pl_dict)}
        volume['provider_location'] = model_update['provider_location']
        return model_update

    def is_flatten_volume(self, volume):
        lun_id = self._extra_lun_or_snap_id(volume)
        err, resp = self.client.is_flatten_lun(lun_id)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif type(resp) is not bool:
            err_msg = 'is flatten volume api fail. id %s resp %s' % (lun_id, resp)
            raise exception.VolumeBackendAPIException(data=err_msg)

        return resp

    def flatten_volume(self, volume):
        lun_id = self._extra_lun_or_snap_id(volume)
        err, resp = self.client.flatten_lun(lun_id)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'flatten volume %s/%s failed with err %s.' % (volume['name'], lun_id, resp['code'])
            raise exception.VolumeBackendAPIException(data=err_msg)

    def get_volume_or_snapshot_size(self, volume):
        lun_or_snap_id = self._extra_lun_or_snap_id(volume)
        err, resp = self.client.get_lun_or_snap_size(lun_or_snap_id)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif resp < 0:
            err_msg = 'can not get volume/snapshot size by id %s err %s' % (lun_or_snap_id, resp)
            raise exception.VolumeBackendAPIException(data=err_msg)

        size_gb = float(resp)/1024/1024/1024
        return size_gb

    def rollback_to_snapshot(self, snapshot):
        snap_id = self._extra_lun_or_snap_id(snapshot)
        err, resp = self.client.rollback_to_snap(snap_id)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'rollback to snapshot %s/%s failed with err %s.' % (snapshot['name'], snap_id, resp['code'])
            raise exception.VolumeBackendAPIException(data=err_msg)

    def _extra_lun_or_snap_id(self, volume):
        if volume.get('provider_location') is None:
            return None
        pl_dict = self._load_provider_location(volume['provider_location'])
        res_type = pl_dict.get('type', None)
        if 'lun' == res_type or 'snap' == res_type:
            if pl_dict.get('id', None):
                return pl_dict['id']
        msg = ('Fail to find LUN ID of %(vol)s in from %(pl)s') % {
            'vol': volume['name'], 'pl': volume['provider_location']}
        if (self.debug): print(msg)
        raise exception.VolumeBackendAPIException(data=msg)

    def delete_volume(self, volume):
        lun_id = self._extra_lun_or_snap_id(volume)
        err, resp = self.client.delete_lun(lun_id)
        if err:
            if not self.client.get_lun_by_id(lun_id):
                if (self.debug): print(_LW("LUN %(name)s is already deleted or does not "
                                "exist. Message: %(msg)s"),
                            {'name': volume['name'], 'msg': err['messages']})
            else:
                raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'delete volume %s/%s failed with err %s.' % (volume['name'], lun_id, resp['code'])
            raise exception.VolumeBackendAPIException(data=err_msg)

    def create_snapshot(self, snapshot, name, snap_desc):
        """This function will create a snapshot of the given volume."""
        print('Entering CCFS3000Helper.create_snapshot.')
        lun_id = self._extra_lun_or_snap_id(snapshot['volume'])
        lun_size = snapshot['volume']['size']
        print('lunid %s, size %s, name %s' % (lun_id, lun_size, name))
        if not lun_id:
            msg = ('Failed to get LUN ID for volume %s') %\
                snapshot['volume']['name']
            raise exception.VolumeBackendAPIException(data=msg)
        err, resp = self.client.create_snap(
            lun_id, name, lun_size, snap_desc)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'create snapshot from volume %s/%s failed with err %s.' % (snapshot['volume']['name'], lun_id, resp['code'])
            raise NameError(err_msg)

        err, snap = self.client.get_snap_by_name(lun_id, name)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not snap:
            err_msg = 'can not get snapshot %(name)s by lun_id %(lun_id)s' % {'name': name, 'lun_id': lun_id}
            raise exception.VolumeBackendAPIException(data=err_msg)

        pl_dict = {'system': self.storage_serial_number,
                   'type': 'snap',
                   'id': snap['Id']}
        model_update = {'provider_location':
                        self._dumps_provider_location(pl_dict)}
        snapshot['provider_location'] = model_update['provider_location']
        return model_update

    def delete_snapshot(self, snapshot):
        """Gets the snap id by the snap name and delete the snapshot."""
        snap_id = self._extra_lun_or_snap_id(snapshot)
        if not snap_id:	#TODO: add log message
            return
        err, resp = self.client.delete_snap(snap_id)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'delete snapshot %s/%s failed with err %s.' % (snapshot['name'], snap_id, resp['code'])
            raise exception.VolumeBackendAPIException(data=err_msg)

    def extend_volume(self, volume, new_size):
        origin_size = volume['size']
        if origin_size >= new_size:
            raise exception.VolumeBackendAPIException("New size for extend must be greater than current size. (current: %s, extended: %s)" % (origin_size, new_size))
        extend_size = new_size - origin_size
        lun_id = self._extra_lun_or_snap_id(volume)
        err, resp = self.client.extend_lun(lun_id, extend_size)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        elif not self._api_exec_success(resp):
            err_msg = 'extend volume %s/%s failed with err %s.' % (volume['name'], lun_id, resp['code'])
            raise exception.VolumeBackendAPIException(data=err_msg)

    def _extract_iscsi_uids(self, connector):
        if 'initiator' not in connector:
            if self.storage_protocol == 'iSCSI':
                msg = ('Host %s has no iSCSI initiator') % connector['host']
                if (self.debug): print(msg)
                raise exception.VolumeBackendAPIException(data=msg)
            else:
                return ()
        return [connector['initiator']]

    def _extract_fc_uids(self, connector):
        if 'wwnns' not in connector or 'wwpns' not in connector:
            if self.storage_protocol == 'FC':
                msg = ('Host %s has no FC initiators') % connector['host']
                if (self.debug): print(msg)
                raise exception.VolumeBackendAPIException(data=msg)
            else:
                return ()
        wwnns = connector['wwnns']
        wwpns = connector['wwpns']
        wwns = [(node + port).upper() for node, port in zip(wwnns, wwpns)]
        return map(lambda wwn: re.sub(r'\S\S',
                                      lambda m: m.group(0) + ':',
                                      wwn,
                                      len(wwn) / 2 - 1),
                   wwns)

    def _categorize_initiators(self, connector):
        if self.storage_protocol == 'iSCSI':
            initiator_uids = self._extract_iscsi_uids(connector)
        elif self.storage_protocol == 'FC':
            initiator_uids = self._extract_fc_uids(connector)
        else:
            initiator_uids = []
        registered_initiators = []
        orphan_initiators = []
        new_initiator_uids = []
        registered_initiators = initiator_uids
        #for initiator_uid in initiator_uids:
        #    initiator = self.client.get_initiator_by_uid(initiator_uid)
        #    if initiator:
        #        initiator = initiator[0]
        #        if 'parentHost' in initiator and initiator['parentHost']:
        #            registered_initiators.append(initiator)
        #        else:
        #            orphan_initiators.append(initiator)
        #    else:
        #        new_initiator_uids.append(initiator_uid)
        return registered_initiators, orphan_initiators, new_initiator_uids

    def _extract_host_id(self, registered_initiators, hostname=None):
        if registered_initiators:
            return registered_initiators[0]['parentHost']['id']
        if hostname:
            host = self.client.get_host_by_name(hostname, ('id',))
            if host:
                return host[0]['id']
        return None

    def _create_initiators(self, new_initiator_uids, host_id):
        for initiator_uid in new_initiator_uids:
            err, initiator = self.client.create_initiator(initiator_uid,
                                                          host_id)
            if err:
                if err['httpStatusCode'] in (409,):
                    if (self.debug): print(_LW('Initiator %s had been created.'),
                                initiator_uid)
                    return
                msg = ('Failed to create initiator %s') % initiator_uid
                if (self.debug): print(msg)
                raise exception.VolumeBackendAPIException(data=msg)

    def _register_initiators(self, orphan_initiators, host_id):
        for initiator in orphan_initiators:
            err, resp = self.client.register_initiator(initiator['id'],
                                                       host_id)
            if err:
                msg = ('Failed to register initiator %(initiator)s '
                        'to %(host)s') % {'initiator': initiator['id'],
                                          'host': host_id}
                if (self.debug): print(msg)
                raise exception.VolumeBackendAPIException(data=msg)

    def _build_init_targ_map(self, mapping):
        """Function to process data from lookup service."""
        #   mapping
        #   {
        #        <San name>: {
        #            'initiator_port_wwn_list':
        #            ('200000051e55a100', '200000051e55a121'..)
        #            'target_port_wwn_list':
        #            ('100000051e55a100', '100000051e55a121'..)
        #        }
        #   }
        target_wwns = []
        init_targ_map = {}

        for san_name in mapping:
            mymap = mapping[san_name]
            for target in mymap['target_port_wwn_list']:
                if target not in target_wwns:
                    target_wwns.append(target)
            for initiator in mymap['initiator_port_wwn_list']:
                init_targ_map[initiator] = mymap['target_port_wwn_list']
        print("target_wwns: %s", target_wwns)
        print("init_targ_map: %s", init_targ_map)
        return target_wwns, init_targ_map

    def arrange_host(self, connector):
        # TODO kevin, single WWPNS now
        if self.storage_protocol == 'FC':
            host_id = connector['wwpns']
        elif self.storage_protocol == 'iSCSI':
            host_id = connector['initiator']
        if host_id is None:
            msg = ('initiator/wwpns is none %s.') % connector
            if (self.debug): print(msg)
            raise exception.VolumeBackendAPIException(data=msg)
            host_id = ''

        return host_id

    def expose_lun(self, lun_data, host_id):
        lun_id = lun_data['Id']
        err, resp = self.client.expose_lun(lun_id, host_id,
                        self.storage_protocol)

        if err:
            msg = ('expose_lun error %s.') % err
            if (self.debug): print(msg)
            raise exception.VolumeBackendAPIException(data=msg)

    def _get_driver_volume_type(self):
        if self.storage_protocol == 'iSCSI':
            return 'iscsi'
        elif self.storage_protocol == 'FC':
            return 'fibre_channel'
        else:
            return 'unknown'

    def _get_fc_zone_info(self, connector, targets):
        initiator_wwns = connector['wwpns']
        target_wwns = [item[1] for item in targets]
        mapping = self.lookup_service_instance.\
            get_device_mapping_from_network(initiator_wwns,
                                            target_wwns)
        target_wwns, init_targ_map = self._build_init_targ_map(mapping)
        return {'initiator_target_map': init_targ_map,
                'target_wwn': target_wwns}

    def _convert_wwns_fs3000_to_openstack(self, wwns):
        """Convert a list of FS3000 WWNs to OpenStack compatible WWN strings.

        Input format is '50:01:43:80:18:6b:3f:65', output format
        is '50014380186b3f65'.

        """
        output = []
        for w in wwns:
            output.append(str(''.join(w[0:].split(':'))))
        return output

    def _build_initiator_target_map(self, connector):
        """Build the target_wwns and the initiator target map."""
        target_wwns = []
        init_targ_map = {}

        initiator_wwns = connector['wwpns']
        for initiator in initiator_wwns:
            active_wwns = self.client.get_active_fc_wwns(str(initiator).upper())
            active_wwns =(self._convert_wwns_fs3000_to_openstack(active_wwns))
            for wwn in active_wwns:
                target_wwns.append(str(wwn))
            init_targ_map[str(initiator).upper()] = active_wwns

        if (self.debug): print("init_targ_map %s target_wwns %s", init_targ_map, target_wwns)
        return {'initiator_target_map': init_targ_map,
                'target_wwn': target_wwns}

    def get_connection_info(self, connector,
                            lun_id, host_id):

        host_lun = self.client.get_host_lun_by_ends(host_id, lun_id,
                                                    self.storage_protocol)
        data = {}
        data['target_lun'] = host_lun
        if self.storage_protocol == 'iSCSI':
            err, target_iqns, target_portals =\
                self._do_iscsi_discovery(self.client.get_active_storage_ip())
            data['target_iqn'] = target_iqns[0]
            data['target_portal'] = target_portals[0]
            # TODO kevin, for multi-connection
            #data['target_iqns'] = target_iqns
            #data['target_portals'] = target_portals
            #data['target_luns'] = [host_lun[0]['hlu']] * len(targets)
        elif self.storage_protocol == 'FC':
            zone_info = self._build_initiator_target_map(connector)
            data.update(zone_info)
            if (CMD_DEBUG == 1):
                print("zone_info %s" % zone_info)

        connection_info = {
            'driver_volume_type': self._get_driver_volume_type(),
            'data': data}
        if (CMD_DEBUG == 1):
            print "conn_info ", connection_info
        return connection_info

    def rescan_host(self):
        hbas = libvirt_utils.get_fc_hbas_info()
        linuxscsi.rescan_hosts(hbas)

    def attach_volume(self, conn_info):
       	if (conn_info['driver_volume_type'] == 'iscsi'):
             self.attach_iscsi(conn_info, self.client.get_active_storage_ip())
       	elif (conn_info['driver_volume_type'] == 'fibre_channel'):
       	     self.rescan_host()
        time.sleep(1)

    def initialize_connection(self, lun_id, connector):
        err, lun_data = self.client.get_lun_by_id(lun_id)
        if (self.storage_protocol == 'iSCSI'):
            host_id = connector['initiator']
        elif (self.storage_protocol == 'FC'):
            host_id = connector['wwpns']
        self.expose_lun(lun_data, host_id)
        conn_info = self.get_connection_info(
                                        connector,
                                        lun_data['Id'],
                                        connector['initiator'])
        self.attach_volume(conn_info)
       	return conn_info

    def _execute(self, command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        outputs, error = process.communicate()
        return outputs, error

    def attach_iscsi(self, conn_info, ip):
        command = 'sudo /usr/bin/iscsiadm -m node -p %s:3260 -l 2>&1 1>/dev/null' % ip
        outputs, error = self._execute(command)
	if (self.debug):
            print ("output, %s" % outputs)

    def detach_iscsi(self, target_portal):
        command = 'sudo /usr/bin/iscsiadm -m node -p %s -u 2>&1 1>/dev/null' % target_portal
        outputs, error = self._execute(command)

        command = 'sudo /usr/bin/iscsiadm -m node -p %s -o delete' % target_portal
        outputs, error = self._execute(command)

    def qemu_img_create(self, backing, to_diff):
        command = 'sudo /usr/bin/qemu-img create -f qcow2 -o backing_file=%s %s' % (backing, to_diff)
        print (command)
        outputs, error = self._execute(command)

    def qemu_img_map(self, nbd_device):
        command = 'sudo /usr/bin/qemu-img map %s' % nbd_device
        outputs, error = self._execute(command)
        maps = []
        for output in outputs.splitlines():
            words = output.split()
            if (words[3] == nbd_device):
                maps.append((words[0], words[1]))
        return maps

    def qemu_img_rebase(self, diff1, diff2):
        command = 'sudo /usr/bin/qemu-img rebase -b %s %s' % (diff1, diff2)
        print (command)
        outputs, error = self._execute(command)

    def connect_nbd(self, to_diff):
        command = '/sbin/modprobe nbd max_part=16'
        outputs, error = self._execute(command)

        nbd_dev = nbd.NbdMount(to_diff, "")
        if (nbd_dev._inner_get_dev()):
            print ('Got %s to %s' % ( nbd_dev.device, nbd_dev.image))
            return nbd_dev
        else:
            raise NameError("Can not get nbd_dev")

    def disconnect_nbd(self, nbd_dev):
        nbd_dev.unget_dev()

    def _do_iscsi_discovery(self, target_ip):
        command = 'sudo /usr/bin/iscsiadm -m discovery -t st -p %s:3260' % target_ip
        targets, error = self._execute(command)
        if (CMD_DEBUG == 1):
             print ("targets, %s, error %s" % (targets, error))
        target_iqns = []
        target_portals = []
        if error != '':
            if (self.debug): print((
                'Can not discovery in %(target_ip)s.'), {
                    'target_ip': target_ip})
            return (False, target_iqns, target_portals)
        else:
            for target in targets.splitlines():
                words = target.split(" ")
                target_iqns.append(words[1])
                target_portals.append(words[0].split(",")[0])

            print("target_iqns %s, portals %s",
                target_iqns, target_portals)
            return (True, target_iqns, target_portals)

        return (False, target_iqns, target_portals)

    def get_path_and_acsl_by_lunid(self, lun_id, conn_info, proto, connector):
        outputs, error = self._execute('sudo /usr/bin/lsscsi -t')

        if (error != '' or outputs is None):
            print('Can not lsscsi.')
            return
        else:
            for output in outputs.splitlines():
                words = output.split( )
                acsl = words[0][1:-1]
                disktype = words[1]
                transport = words[2]
                path = words[3] if (len(words) == 4) else ""

                lun_no = acsl.split(':')[3]
                if (proto == 'iSCSI'):
                    if (conn_info['data']['target_iqn'] in transport and
                        str(lun_no) is str(conn_info['data']['target_lun'])):
                        return path, acsl
                elif (proto == 'FC'):
                    init_target_map = conn_info['data']['initiator_target_map']
                    for init in init_target_map:
                    	for target in init_target_map[init]:
                            if (target in transport.upper() and
                                str(lun_no) is str(conn_info['data']['target_lun'])):
                                return path, acsl
            return

    def hide_lun(self, lun_data, host_id):
        lun_id = lun_data['Id']
        err, resp = self.client.hide_lun(lun_id,
                                         host_id,
                                         self.storage_protocol)
        if err:
            if err['errorCode'] in (0x6701020,):
                if (self.debug): print(_LW('LUN %(lun)s backing %(vol) had been '
                                'hidden from %(host)s.'), {
                            'lun': lun_id, 'vol': lun_data['name'],
                            'host': host_id})
                return
            msg = ('Failed to hide %(vol)s from host %(host)s '
                    ': %(msg)s.') % {'vol': lun_data['name'],
                                     'host': host_id, 'msg': resp}
            raise exception.VolumeBackendAPIException(data=msg)

    def remove_device(self, device):
        linuxscsi.remove_device(linuxscsi.get_device_info(device))

    def terminate_connection(self, lun_id, connector, conn_info, device):
        if self.storage_protocol == 'FC':
            host_id = connector['wwpns']
            self.remove_device(device)
        elif self.storage_protocol == 'iSCSI':
            self.detach_iscsi(conn_info['data']['target_portal'])
            host_id = connector['initiator']

        err, lun_data = self.client.get_lun_by_id(lun_id)
        if (CMD_DEBUG == 1):
            print("terminate_conn lun_id %s, host_id %s, lun_data %s" %
                (lun_id, host_id, lun_data))

        for initiator in host_id:
            self.hide_lun(lun_data, initiator)

        return

    def get_volume_stats(self, refresh=False):
        if refresh:
            self.update_volume_stats()
        return self.stats

    def update_volume_stats(self):
        self.update_slave_storage_ip()

        data = {}
        data['volume_backend_name'] = 'CCFS3000Driver'
        data['storage_protocol'] = self.storage_protocol
        data['driver_version'] = VERSION
        data['vendor_name'] = "Fortunet"

        pools = self.client.get_pools()
        if not pools:
            if (self.debug): print(_LW('update volum stats: can not get pools'))
            return self.stats

        if not self.is_managing_all_pools:
            pools = filter(lambda a: a['Name'] in self.storage_pools_map,
                           pools)
        else:
            self.storage_pools_map = self._build_storage_pool_id_map(pools)
        data['pools'] = map(
            lambda po: self._build_pool_stats(po), pools)

        self.stats = data
        #self.storage_targets = self._get_storage_targets()
        #print('Volume Stats: %s', data)
        return self.stats

    def _build_pool_stats(self, pool):
        pool_stats = {
            'pool_name': pool['Name'],
            'free_capacity_gb': int(pool['Free']) / GiB,
            'total_capacity_gb': int(pool['Size']) / GiB,
            #'provisioned_capacity_gb': pool['sizeSubscribed'] / GiB,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': 0,
            #'thin_provisioning_support': self.thin_enabled,
            'thin_provisioning_support': False,
            'thick_provisioning_support': True,
            'consistencygroup_support': True
            #'max_over_subscription_ratio': self.max_over_subscription_ratio
        }
        return pool_stats

    def do_ls(self, lv_name):
        err, luns = self.client.get_all_type_of_luns()
        fs_lv_name = "%s-volume" % lv_name
        if not err:
            for lun in luns :
                if (lun['Type'] == 'thin Volume' and
                    re.match(fs_lv_name, lun['Name'])):
                    return lun

            for lun in luns :
                if (lun['Type'] == 'thin Volume' and
                    re.match(lv_name, lun['Name'])):
                    return lun

            raise NameError("There's no volume named", lv_name)

    def do_lvs(self):
        err, luns = self.client.get_luns()
        if not err:
            for lun in luns :
                print ('%s, %s') % (lun['Id'], lun['Name'])

    def do_lssnap(self, lv_name):
        lun_data = self.do_ls(lv_name)
        err, snaps = self.client.get_snaps_by_lunid(lun_data['Id'])
        if not err:
            return snaps

    def do_delsnap(self, snap_name):
        lun_data = self.do_ls(snap_name)
        err, resp = self.client.delete_snap(lun_data['Id'])

    def do_det(self, lv_name):
        lun_data = self.do_ls(lv_name)
        lun_id = lun_data['Id']
        conn_info = self.initialize_connection(lun_id, self.connector)
        dev_path, acsl = self.get_path_and_acsl_by_lunid(
                lun_id, conn_info, PROTOCOL, self.connector)
        self.terminate_connection(lun_id, self.connector,
                conn_info, dev_path)
        command = 'for i in /dev/nbd*; do qemu-nbd -d $i; done'
        outputs, error = self._execute(command)

    def _dd_data(self, src_dev, dest_file):
        command = 'sudo /bin/dd if=%s of=%s bs=1M oflag=dsync 2>/dev/null' % (src_dev, dest_file)
        print (command)
        outputs, error = self._execute(command)
        if error != '':
            print('Can not ' , (command, error))
            return

        return

    def _flush_block(self, dest_file):
        command = 'sudo /sbin/blockdev --flushbufs %s' % dest_file
        outputs, error = self._execute(command)
        if error != '':
            print('Can not ' , (command, error))
            return

        return

    def export_vol(self, lv_name, backup_path):
        lun_data = self.do_ls(lv_name)
        lun_id = lun_data['Id']
        conn_info = helper.initialize_connection(lun_id, self.connector)
        dev_path, acsl = self.get_path_and_acsl_by_lunid(lun_id, conn_info, PROTOCOL, self.connector)
        if (CMD_DEBUG == 1):
            print ('******* Got %s dev_path %s, acsl %s' % (lv_name, dev_path, acsl))
        helper._dd_data(dev_path, backup_path)
        self.terminate_connection(lun_id, self.connector, conn_info, dev_path)

    def import_vol(self, backup_path, lv_name):
        lun_data = self.do_ls(lv_name)
        lun_id = lun_data['Id']
        conn_info = helper.initialize_connection(lun_id, self.connector)
        dev_path, acsl = self.get_path_and_acsl_by_lunid(lun_id, conn_info, PROTOCOL, self.connector)
        if (CMD_DEBUG == 1):
            print ('******* Got %s dev_path %s, acsl %s' % (lv_name, dev_path, acsl))
        helper._dd_data(backup_path, dev_path)
        self.terminate_connection(lun_id, self.connector, conn_info, dev_path)

    def export_diff(self, from_snap, lv_name, to_snap, to_diff, to_nbd):
        lun_data = self.do_ls(lv_name)
        lun_data1 = self.do_ls(from_snap)
        lun_data2 = self.do_ls(to_snap)

        lun_id = lun_data2['Id']
        conn_info = helper.initialize_connection(lun_id, self.connector)
        dev_path, acsl = self.get_path_and_acsl_by_lunid(lun_id, conn_info, PROTOCOL, self.connector)
        if (CMD_DEBUG == 1):
            print ('******* Got %s dev_path %s, acsl %s' % (to_snap, dev_path, acsl))
        if (to_nbd == 0):
            self._export_rdiff(dev_path, to_diff, lun_data1, lun_data2, lun_data)
        else:
            self._export_qdiff(dev_path, to_diff, lun_data1, lun_data2, lun_data)
        self.terminate_connection(lun_id, self.connector, conn_info, dev_path)

    def _export_rdiff(self, src_path, to_diff, fs_lun, ts_lun, orig_lun):
        input_offset = 0;
        output_offset = 0;
        in_fp = open(src_path, "rb");
        out_fp = open(to_diff, "wb");
        if (CMD_DEBUG == 1):
            print ("#####: infp %s, outfp %s" % (src_path, to_diff))

        # Write Protocol header
        out_fp.write(RBD_PROTO_HDR);
        output_offset += RBD_PROTO_HDR_SIZE
        out_fp.seek(output_offset)

        # Write 'From snap'
        out_fp.write('f');
        output_offset += 1
        out_fp.seek(output_offset)

        output_buffer = struct.pack('<I', len(fs_lun['Name']))
        out_fp.write(output_buffer);
        output_offset += 4
        out_fp.seek(output_offset)

        out_fp.write(fs_lun['Name']);
        output_offset += len(fs_lun['Name'])
        out_fp.seek(output_offset)

        # Write 'To snap'
        out_fp.write('t');
        output_offset += 1
        out_fp.seek(output_offset)

        output_buffer = struct.pack('<I', len(ts_lun['Name']))
        out_fp.write(output_buffer);
        output_offset += 4
        out_fp.seek(output_offset)

        out_fp.write(ts_lun['Name']);
        output_offset += len(ts_lun['Name'])
        out_fp.seek(output_offset)

        # Write LV size
        out_fp.write('s');
        output_offset += 1
        out_fp.seek(output_offset)

        output_buffer = struct.pack('<Q', int(orig_lun['Size']))
        out_fp.write(output_buffer);
        output_offset += 8
        out_fp.seek(output_offset)

        # Write diff data
        err, diff_map = self.client.get_thin_dump_diff(fs_lun['Id'], ts_lun['Id'])
        if (diff_map is None):
            if (CMD_DEBUG == 1):
                print "There's no diff between", fs_lun['Name'], ts_lun['Name']
                print "Error ", err
            # Write end
            out_fp.write('e');
            output_offset += 1
            out_fp.seek(output_offset)

            in_fp.close()
            out_fp.close()
            return

        diff_map = diff_map['code']

        for map in diff_map:
            bs =  map['chunksize']
            start =  map['start'] * bs
            length =  map['length'] * bs
            if (CMD_DEBUG == 1):
                print 'start %s, len %s, bs %s' % (map['start'], map['length'], map['chunksize'])

            out_fp.write('w');
            output_offset += 1
            out_fp.seek(output_offset)

            output_buffer = struct.pack('<QQ', start, length)
            out_fp.write(output_buffer);
            output_offset += 16
            out_fp.seek(output_offset)

            in_fp.seek(start)
            out_fp.write(in_fp.read(length));
            output_offset += length
            out_fp.seek(output_offset)

        # Write end
        out_fp.write('e');
        output_offset += 1
        out_fp.seek(output_offset)

        in_fp.close()
        out_fp.close()
        return

    def _export_qdiff(self, src_path, to_diff, fs_lun, ts_lun, orig_lun):
        in_fp = open(src_path, "rb");
        out_fp = open(to_diff, "wb");
        if (CMD_DEBUG == 1):
            print ("#####: infp %s, outfp %s" % (src_path, to_diff))

        # Write diff data
        err, diff_map = self.client.get_thin_dump_diff(fs_lun['Id'], ts_lun['Id'])
        if (diff_map is None):
            if (CMD_DEBUG == 1):
                print "There's no diff between", fs_lun['Name'], ts_lun['Name']
                print "Error ", err

            in_fp.close()
            out_fp.close()
            return

        diff_map = diff_map['code']

        for map in diff_map:
            bs =  map['chunksize']
            start =  map['start'] * bs
            length =  map['length'] * bs
            if (CMD_DEBUG == 1):
                print 'start %s, len %s, bs %s' % (map['start'], map['length'], map['chunksize'])

            in_fp.seek(start)
            out_fp.seek(start)
            out_fp.write(in_fp.read(length));

        in_fp.close()
        out_fp.close()
        return

    def import_rdiff(self, backup, lv_name):
        lun_data = self.do_ls(lv_name)
        if (lun_data is None):
             print ("[Error] There is no %s" % lv_name)
             return

        conn_info = self.initialize_connection(lun_data['Id'], self.connector)
        dev_path, acsl = self.get_path_and_acsl_by_lunid(
             lun_data['Id'], conn_info, PROTOCOL, self.connector)
        if (CMD_DEBUG == 1):
            print ('******* Got %s dev_path %s, acsl %s' % (lv_name, dev_path, acsl))
        self._import_rdiff(backup, dev_path, lun_data)
        self.terminate_connection(lun_data['Id'], self.connector, conn_info, dev_path)

    def export_qdiff(self, from_snap, lv_name, to_snap, to_diff, backing):
        self.qemu_img_create(backing, to_diff)
        nbd_dev = self.connect_nbd(to_diff)
        self.export_diff(from_snap, lv_name, to_snap, nbd_dev.device, 1)
        nbd_dev.flush_dev()
        self.disconnect_nbd(nbd_dev)
        pass

    def import_qdiff(self, backup, lv_name):
        lun_data = self.do_ls(lv_name)
        if (lun_data is None):
             print ("[Error] There is no %s found in fs3000" % lv_name)
             return

        nbd_dev = self.connect_nbd(backup)
        conn_info = self.initialize_connection(lun_data['Id'], self.connector)
        dev_path, acsl = self.get_path_and_acsl_by_lunid(
             lun_data['Id'], conn_info, PROTOCOL, self.connector)
        if (CMD_DEBUG == 1):
            print ('******* Got %s dev_path %s, acsl %s' % (lv_name, dev_path, acsl))
        self._import_qdiff(nbd_dev, dev_path, lun_data)
        self._flush_block(dev_path)
        nbd_dev.flush_dev()
        self.disconnect_nbd(nbd_dev)
        self.terminate_connection(lun_data['Id'], self.connector, conn_info, dev_path)

    def parse_rbd_meta(self, in_fp, input_offset):
        # Read LV size starting tag 'w'
        input_buffer = in_fp.read(1);
        input_offset += 1
        in_fp.seek(input_offset)
        if (input_buffer != 'w'):
            return 0,0,0

        input_buffer = in_fp.read(16)
        if (len(input_buffer) != 16):
            return 0,0,0

        start, length = struct.unpack('<QQ', input_buffer)
        if length == 0:
            return 0,0,0

        input_offset += 16
        in_fp.seek(input_offset)

        return start, length, input_offset

    def parse_rbd_hdr(self, in_fp):
        # Read Protocol header
        input_offset = 0
        input_buffer = in_fp.read(RBD_PROTO_HDR_SIZE);
        input_offset += RBD_PROTO_HDR_SIZE
        in_fp.seek(input_offset)

        # Read From snap starting tag 'f'
        input_buffer = in_fp.read(1);
        input_offset += 1
        in_fp.seek(input_offset)
        if (input_buffer != 'f'):
            raise NameError("There's no from snap")

        input_buffer = in_fp.read(4);
        input_offset += 4
        in_fp.seek(input_offset)
        fsnap_length = struct.unpack('<I', input_buffer)[0]

        input_buffer = in_fp.read(int(fsnap_length));
        input_offset += fsnap_length
        in_fp.seek(input_offset)
        fsnap = input_buffer

        # Read To snap starting tag 't'
        input_buffer = in_fp.read(1);
        input_offset += 1
        in_fp.seek(input_offset)
        if (input_buffer != 't'):
            raise NameError("There's no to snap")

        input_buffer = in_fp.read(4);
        input_offset += 4
        in_fp.seek(input_offset)
        tsnap_length = struct.unpack('<I', input_buffer)[0]

        input_buffer = in_fp.read(int(tsnap_length));
        input_offset += tsnap_length
        in_fp.seek(input_offset)
        tsnap = input_buffer

        # Read LV size starting tag 's'
        input_buffer = in_fp.read(1);
        input_offset += 1
        in_fp.seek(input_offset)
        if (input_buffer != 's'):
            raise NameError("There's no size")

        input_buffer = in_fp.read(8);
        input_offset += 8
        in_fp.seek(input_offset)
        lv_size = struct.unpack('<Q', input_buffer)[0]

        return fsnap, tsnap, lv_size, input_offset

    def _import_rdiff(self, backup_file, dest_path, orig_lun):
        in_fp = open(backup_file, "rb");
        out_fp = open(dest_path, "wb");
        fsnap, tsnap, lv_size, input_offset = self.parse_rbd_hdr(in_fp)
        if (CMD_DEBUG == 1):
            print "import ", (fsnap, tsnap, lv_size, input_offset)

        # Create From snapshot named 'fsnap' for orig_lun
        err, lun_data = self.client.get_lun_by_name(fsnap)
        if ((lun_data is None) or (lun_data['Origin'] != orig_lun['Id'])):
            print "create snapshot %s for %s" % (fsnap, orig_lun['Name'])
            snapshot = {'name': fsnap,
                        'size': int(orig_lun['Size'])/GiB,
                        'volume_name': orig_lun['Id'],
                        'display_name': 'fs3000_backup.py created',
                        'volume': {'provider_location': ('type^lun|system^TODO_HA|id^%s' % orig_lun['Id']),
                                   'name': orig_lun['Id'],
                                   'size': int(orig_lun['Size'])/GiB}}
            if (CMD_DEBUG == 1):
                print "#####: fsnapshot %s" % snapshot
            self.create_snapshot(snapshot, fsnap, "fs3000_backup created")

        while 1:
            start, length, input_offset = self.parse_rbd_meta(in_fp, input_offset)
            if (length == 0):
                break
            out_fp.seek(start)
            out_fp.write(in_fp.read(length));
            input_offset += length
            in_fp.seek(input_offset)

        in_fp.close()
        out_fp.close()

        # Create To snapshot named 'tsnap' for orig_lun
        err, lun_data = self.client.get_lun_by_name(tsnap)
        if ((lun_data is None) or (lun_data['Origin'] != orig_lun['Id'])):
            print "create snapshot %s for %s" % (tsnap, orig_lun['Name'])
            snapshot = {'name': tsnap,
                        'size': int(orig_lun['Size'])/GiB,
                        'volume_name': orig_lun['Id'],
                        'display_name': 'fs3000_backup.py created',
                        'volume': {'provider_location': ('type^lun|system^TODO_HA|id^%s' % orig_lun['Id']),
                                   'name': orig_lun['Id'],
                                   'size': int(orig_lun['Size'])/GiB}}
            if (CMD_DEBUG == 1):
                print "#####: tsnapshot %s" % snapshot
            self.create_snapshot(snapshot, tsnap, "fs3000_backup created")

    def _import_qdiff(self, nbd_dev, dest_path, orig_lun):
        in_fp = open(nbd_dev.device, "rb");
        out_fp = open(dest_path, "wb");
        if (CMD_DEBUG == 1):
            print "in_fp %s, out_fp %s" % (nbd_dev.device, dest_path)
        maps = self.qemu_img_map(nbd_dev.image)
        # create From snapshot if need
        #err, snaps = self.client.get_snaps_by_lunid(orig_lun['Id'])
        #if not snaps:
        #    fsnap = strftime("%Y%m%d_%H%M%S", gmtime())
        #    snapshot = {'name': fsnap,
        #                'size': int(orig_lun['Size'])/GiB,
        #                'volume_name': orig_lun['Id'],
        #                'display_name': 'fs3000_backup.py created',
        #                'volume': {'provider_location': ('type^lun|system^TODO_HA|id^%s' % orig_lun['Id']),
        #                           'name': orig_lun['Id'],
        #                           'size': int(orig_lun['Size'])/GiB}}
        #    if (CMD_DEBUG == 1):
        #        print "#####: fsnapshot %s" % snapshot
        #    self.create_snapshot(snapshot, fsnap, "fs3000_backup created")

        for map in maps:
            (start, length) = map
            start = int(start, 16)
            length = int(length, 16)
            if (CMD_DEBUG == 1):
                print "#####: map: ", map, start, length
            in_fp.seek(start)
            out_fp.seek(start)
            out_fp.write(in_fp.read(length))

        in_fp.close()
        out_fp.close()

        # always create To snapshot after import diff after at least 1s
        #time.sleep(1)
        #tsnap = strftime("%Y%m%d_%H%M%S", gmtime())
        #snapshot = {'name': tsnap,
        #            'size': int(orig_lun['Size'])/GiB,
        #            'volume_name': orig_lun['Id'],
        #            'display_name': 'fs3000_backup.py created',
        #            'volume': {'provider_location': ('type^lun|system^TODO_HA|id^%s' % orig_lun['Id']),
        #                       'name': orig_lun['Id'],
        #                       'size': int(orig_lun['Size'])/GiB}}
        #if (CMD_DEBUG == 1):
        #    print "#####: tsnapshot %s" % snapshot
        #self.create_snapshot(snapshot, tsnap, "fs3000_backup created")

    def do_merge_rdiff(self, diff1, diff2, diff3):
        diff1_fp = open(diff1, "rb");
        diff2_fp = open(diff2, "rb");
        fsnap1, tsnap1, lv_size1, input_offset1 = self.parse_rbd_hdr(diff1_fp)
        fsnap2, tsnap2, lv_size2, input_offset2 = self.parse_rbd_hdr(diff2_fp)
        if (CMD_DEBUG == 1):
            print "diff1 ", (fsnap1, tsnap1, lv_size1, input_offset1)
            print "diff2 ", (fsnap2, tsnap2, lv_size2, input_offset2)

        # Sanity Check
        if (tsnap1 != fsnap2):
            raise NameError("The first TO snapshot must be equal with the" \
                            " second FROM snapshot, aborting")
        diff1_map = {}
        diff2_map = {}
        while 1:
            # Read LV size starting tag 'w'
            input_buffer = in_fp.read(1);
            input_offset += 1
            in_fp.seek(input_offset)
            if (input_buffer != 'w'):
                break

            input_buffer = in_fp.read(16)
            if (len(input_buffer) != 16):
                break
            start, length = struct.unpack('<QQ', input_buffer)
            if length == 0:
                break
            input_offset += 16
            in_fp.seek(input_offset)

            out_fp.seek(start)
            out_fp.write(in_fp.read(length));

            input_offset += length
            in_fp.seek(input_offset)

            if (CMD_DEBUG == 1):
                print ("#####: start %s len %s" % (start, length))

        return

    def do_merge_qdiff(self, diff1, diff2):
        self.qemu_img_rebase(diff1, diff2)

def main():

    Usage = 'Usage:\n\
     # fs3000_backup.py export LV_NAME dest-path\n\
     # fs3000_backup.py import src-path LV_NAME\n\
     # fs3000_backup.py export-diff from_snap1 LV_NAME@snap2 dest-path backing-path\n\
     # fs3000_backup.py import-diff /path/to/diff LV_NAME\n\
     # fs3000_backup.py merge-diff 1st-diff-path 2nd-diff-path\n\
     # Note: the diffs between 1st-diff and 2nd-diff will be merged to 2nd-diff\n\
    '


    if (sys.argv[1] == 'export'):
        if (len(sys.argv) != 4):
            print Usage
            return
        lv_name = sys.argv[2]
        backup_path = sys.argv[3]

        helper.export_vol(lv_name, backup_path)

    elif (sys.argv[1] == 'import'):
        if (len(sys.argv) != 4):
            print Usage
            return
        backup_path = sys.argv[2]
        lv_name = sys.argv[3]

        helper.import_vol(backup_path, lv_name)

    elif (sys.argv[1] == 'export-rdiff'):
        if (len(sys.argv) != 5):
            print Usage
            return
        from_snap = sys.argv[2]
        word = sys.argv[3].split("@")
        lv_name = word[0]
        to_snap = word[1]
        to_diff = sys.argv[4]

        helper.export_diff(from_snap, lv_name, to_snap, to_diff, 0)

    elif (sys.argv[1] == 'import-rdiff'):
        if (len(sys.argv) != 4):
            print Usage
            return
        backup_file = sys.argv[2]
        lv_name = sys.argv[3]

        helper.import_rdiff(backup_file, lv_name)

    elif (sys.argv[1] == 'export-diff'):
        if (len(sys.argv) != 6):
            print Usage
            return
        from_snap = sys.argv[2]
        word = sys.argv[3].split("@")
        lv_name = word[0]
        to_snap = word[1]
        to_diff = sys.argv[4]
        backing = sys.argv[5]

        helper.export_qdiff(from_snap, lv_name, to_snap, to_diff, backing)

    elif (sys.argv[1] == 'import-diff'):
        if (len(sys.argv) != 4):
            print Usage
            return
        backup_file = sys.argv[2]
        lv_name = sys.argv[3]

        helper.import_qdiff(backup_file, lv_name)

    elif (sys.argv[1] == 'merge-diff'):
        if (len(sys.argv) != 4):
            print Usage
            return
        first_diff = sys.argv[2]
        second_diff = sys.argv[3]

        helper.do_merge_qdiff(first_diff, second_diff)

    elif (sys.argv[1] == 'ls'):
        if (len(sys.argv) != 3):
            return
        lun_data = helper.do_ls(sys.argv[2])
        print (lun_data['Id'], lun_data['Name'])

    elif (sys.argv[1] == 'lvs'):
        helper.do_lvs()

    elif (sys.argv[1] == 'lssnap'):
        if (len(sys.argv) != 3):
            return
        snaps = helper.do_lssnap(sys.argv[2])
        for snap in snaps:
            print(str(snap['Id']), str(snap['Name']))

    elif (sys.argv[1] == 'delsnap'):
        if (len(sys.argv) != 3):
            return
        helper.do_delsnap(sys.argv[2])

    elif (sys.argv[1] == 'detach'):
        if (len(sys.argv) != 3):
            return
        helper.do_det(sys.argv[2])

    else:
        print Usage
        return

helper = CCFS3000Helper(PROTOCOL, HTTP_DEBUG)
if __name__ == "__main__":
    main()
