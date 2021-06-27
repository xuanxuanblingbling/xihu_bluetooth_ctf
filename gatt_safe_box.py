#!/usr/bin/env python3

import os
import sys
import time
import array
import logging
import threading
import subprocess

from random import randint

import dbus
import dbus.mainloop.glib
import dbus.service

from dbus import SystemBus
from dbus import ObjectPath
from dbus.exceptions import DBusException
from dbus import INTROSPECTABLE_IFACE

from Crypto.Cipher import AES

# sys.path.insert(0, '/mnt/hgfs/OneDrive/Projects/bthci/src')
from bthci import HCI
from pyclui import DEBUG, INFO, WARNING, ERROR

try:
    from gi.repository import GObject
except ImportError:
    import gobject as GObject


mainloop = None

IFACE_OBJ_MGR = 'org.freedesktop.DBus.ObjectManager'
IFACE_PROP = 'org.freedesktop.DBus.Properties'

BLUEZ_NAME = 'org.bluez' # The well-known name of bluetoothd
IFACE_GATT_MGR_1 = 'org.bluez.GattManager1'
IFACE_GATT_SVC_1 = 'org.bluez.GattService1'
IFACE_GATT_CHARAC_1 = 'org.bluez.GattCharacteristic1'
IFACE_GATT_DESC_1 = 'org.bluez.GattDescriptor1'


current_battery_level = None
KEYS = [
    bytes([86, 109, 89, 90, 87, 89, 101, 50, 120, 71, 112, 121, 49, 73, 102, 107]),
    bytes([109, 53, 53, 71, 82, 121, 87, 122, 55, 106, 107, 54, 85, 76, 57, 79]),
    bytes([55, 68, 122, 50, 85, 121, 97, 80, 84, 89, 97, 73, 78, 79, 104, 84]),
    bytes([55, 68, 85, 52, 120, 112, 119, 79, 97, 66, 69, 57, 100, 86, 110, 117]),
    bytes([53, 118, 113, 117, 78, 88, 49, 80, 90, 117, 97, 116, 71, 68, 52, 88]),
    bytes([86, 54, 84, 78, 83, 69, 114, 104, 88, 80, 103, 100, 74, 83, 90, 85]),
    bytes([56, 114, 114, 107, 99, 66, 83, 119, 57, 57, 50, 56, 112, 120, 109, 106]),
    bytes([114, 89, 65, 54, 120, 109, 57, 109, 80, 49, 103, 113, 100, 73, 116, 90]),
    bytes([100, 120, 106, 52, 105, 119, 88, 80, 66, 82, 80, 77, 50, 117, 107, 52]),
    bytes([108, 114, 121, 48, 67, 114, 80, 53, 72, 68, 71, 76, 53, 86, 113, 89])
]
current_key = KEYS[1]


class InvalidArgsException(DBusException):
    _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'


class NotSupportedException(DBusException):
    _dbus_error_name = 'org.bluez.Error.NotSupported'


class NotPermittedException(DBusException):
    _dbus_error_name = 'org.bluez.Error.NotPermitted'


class InvalidValueLengthException(DBusException):
    _dbus_error_name = 'org.bluez.Error.InvalidValueLength'


class FailedException(DBusException):
    _dbus_error_name = 'org.bluez.Error.Failed'


class Service(dbus.service.Object):
    '''org.bluez.GattService1 interface implementation'''
    def __init__(self, bus, idx, uuid:str, primary=True):
        '''
        bus - 当前的 object 导出到哪一个 bus 上。
        idx - 指定当前 service 的编号,用于构造 Service 对象的 path.
        uuid - service UUID
        primary - Indicates whether this GATT service is a primary service. 
                  If false, the service is secondary.
        '''
        self.path = '/x/gatt_safe_box/service' + str(idx)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characs = []

        super().__init__(bus, self.path)


    def get_properties(self):
        return {
            IFACE_GATT_SVC_1: {
                'UUID': self.uuid,
                'Primary': self.primary,
                'Characteristics': dbus.Array(
                    self.get_charac_paths(), signature='o')
            }
        }


    def get_charac_paths(self) -> list:
        '''Return all object paths of the Characteristics belonging to this Service'''
        result = []
        for charac in self.characs:
            result.append(ObjectPath(charac.path))
        return result


    @dbus.service.method(IFACE_PROP, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != IFACE_GATT_SVC_1:
            raise InvalidArgsException()

        return self.get_properties()[IFACE_GATT_SVC_1]


class Characteristic(dbus.service.Object):
    '''org.bluez.GattCharacteristic1 interface implementation'''

    def __init__(self, bus, idx, uuid, flags, service):
        '''
        idx - 但前 Characteristc 的编号,用于构造其 object path
        server - 该 characteristic 所属的 service.
        '''
        self.path = service.path + '/characteristic' + str(idx)
        self.bus = bus
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.descriptors = []
        super().__init__(bus, self.path)


    def get_properties(self):
        return {
            IFACE_GATT_CHARAC_1: {
                'Service': ObjectPath(self.service.path),
                'UUID': self.uuid,
                'Flags': self.flags,
                'Descriptors': dbus.Array(
                    self.get_descriptor_paths(),
                    signature='o')
            }
        }


    def get_descriptor_paths(self):
        result = []
        for desc in self.descriptors:
            result.append(ObjectPath(desc.path))
        return result


    @dbus.service.method(IFACE_PROP, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != IFACE_GATT_CHARAC_1:
            raise InvalidArgsException()

        return self.get_properties()[IFACE_GATT_CHARAC_1]


    @dbus.service.method(IFACE_GATT_CHARAC_1, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        print('Default ReadValue called, returning error')
        raise NotSupportedException()


    @dbus.service.method(IFACE_GATT_CHARAC_1, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        print('Default WriteValue called, returning error')
        raise NotSupportedException()


    @dbus.service.method(IFACE_GATT_CHARAC_1)
    def StartNotify(self):
        print('Default StartNotify called, returning error')
        raise NotSupportedException()


    @dbus.service.method(IFACE_GATT_CHARAC_1)
    def StopNotify(self):
        print('Default StopNotify called, returning error')
        raise NotSupportedException()


    @dbus.service.signal(IFACE_PROP, signature='sa{sv}as')
    def PropertiesChanged(self, interface, changed, invalidated):
        pass


class Descriptor(dbus.service.Object):
    '''org.bluez.GattDescriptor1 interface implementation'''
    def __init__(self, bus, index, uuid, flags, charac):
        self.path = charac.path + '/descriptor' + str(index)
        self.bus = bus
        self.uuid = uuid
        self.flags = flags
        self.charac = charac
        super().__init__(bus, self.path)


    def get_properties(self):
        return {
            IFACE_GATT_DESC_1: {
                'Characteristic': ObjectPath(self.charac.path),
                'UUID': self.uuid,
                'Flags': self.flags,
            }
        }


    @dbus.service.method(IFACE_PROP, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != IFACE_GATT_DESC_1:
            raise InvalidArgsException()

        return self.get_properties()[IFACE_GATT_DESC_1]


    @dbus.service.method(IFACE_GATT_DESC_1, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        print('Default ReadValue called, returning error')
        raise NotSupportedException()


    @dbus.service.method(IFACE_GATT_DESC_1, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        print('Default WriteValue called, returning error')
        raise NotSupportedException()


class RootObject(dbus.service.Object):
    '''org.bluez.GattApplication1 interface implementation'''
    def __init__(self, bus, bus_name=None):
        self.path = '/'
        self.services = [
            BatteryService(bus, 0),
            SafeBoxService(bus, 1)
        ]
        super().__init__(bus, self.path, bus_name)


    @dbus.service.method(IFACE_OBJ_MGR, out_signature='a{oa{sa{sv}}}')
    def GetManagedObjects(self):
        '''bluetoothd 会调用这个方法获取我们实现的各种 services'''
        print(DEBUG, 'RootObject, GetManagedObjects')
        
        rsp = {}
        for service in self.services:
            rsp[ObjectPath(service.path)] = service.get_properties()
            for charac in service.characs:
                rsp[ObjectPath(charac.path)] = charac.get_properties()
                for desc in charac.descriptors:
                    rsp[ObjectPath(desc.path)] = desc.get_properties()

        # print(DEBUG, 'Application GetManagedObjects rsp:', rsp)
        return rsp


    @dbus.service.method(INTROSPECTABLE_IFACE, in_signature='', 
        out_signature='s', path_keyword='path', connection_keyword='conn')
    def Introspect(self, path, conn):
        '''
        Although we can inherit the Introspect() implemented by 
        dbus.service.Object, but for ease of debugging, we still implement our 
        own Introspect().
        
        obj_path - Object path passed when the method is called by another 
                   apps.
        conn     - The bus to which app to which the object belongs is connected.
        '''
        print(DEBUG, 'RootObject Introspect')
        print('\tpath:', path)
        print('\tconn:', conn)
        return super().Introspect(path, conn)


class BatteryService(Service):
    uuid = 0x180f
    uuid_str = '%04x'%uuid

    def __init__(self, bus, idx):
        super().__init__(bus, idx, self.uuid_str)
        self.characs = [
            BatteryLevelCharac(bus, 0, self)
        ]


class BatteryLevelCharac(Characteristic):
    uuid = 0x2a19
    uuid_str = '%04x'%uuid

    def __init__(self, bus, idx, service):
        super().__init__(bus, idx, self.uuid_str, 
            ['read', 'notify'], service)

        self.cccd = BatteryLevelCCCD(bus, 0, self)
        self.descriptors = [self.cccd]

        self.notifying = False
        self.battery_level = 100
        self.charging = False


    def notify_battery_level_callback(self):
        global current_battery_level
        global current_key

        if self.notifying:
            self.battery_level = randint(1, 10) * 10
            current_battery_level = self.battery_level
            current_key = KEYS[int(current_battery_level/10) - 1]
            print(INFO, 'Current battery level: ', current_battery_level)
            print(INFO, 'Current key:', current_key)

            self.PropertiesChanged(IFACE_GATT_CHARAC_1,
                {'Value': [dbus.Byte(self.battery_level)]}, []
            )

        return True


    def ReadValue(self, options):
        print(DEBUG, 'BatteryLevelCharac, ReadValue')
        print('\toptions:', options)
        # print('\t', repr(self.battery_level), sep='')
        return [dbus.Byte(self.battery_level)]


    def StartNotify(self):
        print(DEBUG, 'BatteryLevelCharac', 'StartNotify')
        if self.notifying:
            print(DEBUG, 'BatteryLevelCharac', 'Already notifying, nothing to do')
        else:
            # 每隔 1 秒更改一次 battery level,即 key 的索引
            # 时间太长会导致客户端收不到数据
            self.notifying = True
            GObject.timeout_add(2000, self.notify_battery_level_callback)


    def StopNotify(self):
        print(DEBUG, 'BatteryLevelCharac', 'StopNotify')
        if not self.notifying:
            print(DEBUG, 'BatteryLevelCharac', 'Not notifying, nothing to do')
            return

        self.notifying = False


class BatteryLevelCCCD(Descriptor):
    uuid = 0x2902
    uuid_str = '%04x'%uuid

    def __init__(self, bus, idx, charac):
        super().__init__(bus, idx, self.uuid_str, ['read', 'write'], charac)
        self.value = 0x0000
        self.notifi_flag = self.value & 0x0001
        self.indic_flag = self.value >> 1 & 0x0001

    def ReadValue(self, options):
        print(DEBUG, 'BatteryLevelCCCD', 'ReadValue')
        return [
            dbus.Byte('T'), dbus.Byte('e'), dbus.Byte('s'), dbus.Byte('t')
        ]


class SafeBoxService(Service):
    uuid_str = '12345678-1234-5678-1234-56789abcdef0'

    def __init__(self, bus, idx):
        super().__init__(bus, idx, self.uuid_str)
        self.characs = [
            LockCharac(bus, 0, self),
            BackdoorCharac(bus, 1, self)
        ]


class LockCharac(Characteristic):
    uuid_str = '11111111-1111-1111-1111-111111111111'
    # tip = 'What a strange battery level!'
    tip = 'Strange battery level'

    def __init__(self, bus, idx, service):
        super().__init__(bus, idx, self.uuid_str, 
            ['read', 'write', 'notify'], service)
        self.notifying = False
        self.notify_current_key = False 


    def notify_key_callback(self):
        '''告诉玩家当前的密钥'''
        if self.notifying:
            if self.notify_current_key:
                print(INFO, 'Notify current key:', current_key)
                self.PropertiesChanged(IFACE_GATT_CHARAC_1,
                    {'Value': dbus.ByteArray(current_key)}, [])

        self.notify_current_key = False
        return True


    def ReadValue(self, options) -> dbus.ByteArray:
        print(DEBUG, 'LockCharac, ReadValue')
        print('\toptions:', options)
        # print('\t', dbus.ByteArray(self.tip.encode()), seq='')
        return dbus.ByteArray(self.tip.encode()) # 太长的话 bluescan 会出问题，是 bluescan 的 bug
        

    def WriteValue(self, value, options):
        print(DEBUG, 'LockCharac, WriteValue')
        # print('\tvalue:', value)
        # print('\toptions:', options)
        try:
            if int.from_bytes(value, byteorder='little', signed=False) == current_battery_level:
                print(INFO, 'Battery level match')
                self.notify_current_key = True
        except:
            pass


    def StartNotify(self):
        print(DEBUG, 'LockCharac', 'StartNotify')
        if self.notifying:
            print(DEBUG, 'LockCharac', 'Already notifying, nothing to do')
        else:
            self.notifying = True
            GObject.timeout_add(1000, self.notify_key_callback)


    def StopNotify(self):
        print(DEBUG, 'LockCharac', 'StopNotify')
        if not self.notifying:
            print(DEBUG, 'LockCharac', 'Not notifying, nothing to do')
        else:
            self.notifying = False


class BackdoorCharac(Characteristic):
    uuid_str = '11111111-1111-1111-1111-111111111110'
    # tip = 'Do you have random keys to solve this challenge?'
    tip = 'Random key challenge'
    plaintext = 'DBAPPSecurHatLab'
    FLAG = 'flag_6onT@ttach_bkdr'

    def __init__(self, bus, idx, service):
        super().__init__(bus, idx,
            self.uuid_str, ['read', 'write', 'notify'], service)

        self.value = self.tip
        self.descriptors = [
            BackdoorCCCD(bus, 0, self)
        ]

        self.hit_count = 0
        self.notifying = False
        self.notify_flag = False


    def notify_callback(self):
        if self.notifying:
            if self.notify_flag:
                self.PropertiesChanged(IFACE_GATT_CHARAC_1,
                    {'Value': dbus.ByteArray(self.FLAG.encode())}, [])
                self.notify_flag = False
            else:
                self.PropertiesChanged(IFACE_GATT_CHARAC_1,
                    {'Value': dbus.ByteArray(self.plaintext.encode())}, [])

        return True


    def ReadValue(self, options):
        print(DEBUG, 'BackdoorCharac, ReadValue')
        # print('\toptions:', options)
        # print('\t', list(dbus.ByteArray(self.tip.encode())), seq='')
        return dbus.ByteArray(self.tip.encode())


    def WriteValue(self, value, options):
        print(DEBUG, 'BackdoorCharac, WriteValue')
        # print('\tvalue:', value)
        # print('\toptions:', options)

        global current_key

        try:
            plaintext_bin = AES.new(current_key, AES.MODE_ECB).decrypt(bytes(value))
            print(INFO, 'plaintext_bin', plaintext_bin)
            if plaintext_bin.decode() == self.plaintext:
                self.hit_count += 1
            else:
                self.hit_count = 0
            print(INFO, 'Hit count:', self.hit_count)

            if self.hit_count == 10:
                self.notify_flag = True


            if self.hit_count == 15:
                self.hit_count == 0
        except:
            pass

    def StartNotify(self):
        print(DEBUG, 'BackdoorCharac', 'StartNotify')
        if self.notifying:
            print(DEBUG, 'BackdoorCharac', 'Already notifying, nothing to do')
        else:
            self.notifying = True
            GObject.timeout_add(1000, self.notify_callback)


    def StopNotify(self):
        print(DEBUG, 'BackdoorCharac', 'StopNotify')
        if not self.notifying:
            print('Not notifying, nothing to do')
        else:
            self.notifying = False


class BackdoorCCCD(Descriptor):
    uuid = 0x2902
    uuid_str = '%04x'%uuid

    def __init__(self, bus, index, charac):
        super().__init__(bus, index,
            self.uuid_str, ['read', 'write'], charac)

    def ReadValue(self, options):
        print(INFO, 'BackdoorCCCD')
        return [
            dbus.Byte('T'), dbus.Byte('e'), dbus.Byte('s'), dbus.Byte('t')
        ]

    def WriteValue(self, value, options):
        print('BackdoorDescriptor, WriteValue: ' + repr(value))
        self.value = value


def register_app_callback():
    print(INFO, 'RootObject registered')


def register_app_error_callback(error):
    print(ERROR, 'Failed to register root object:', error)
    mainloop.quit()


def find_gatt_hci_obj_path(bus:SystemBus, iface:str) -> str:
    '''return - HCI object path'''
    objs = dbus.Interface(
        bus.get_object(BLUEZ_NAME, '/'), IFACE_OBJ_MGR
    ).GetManagedObjects()

    for obj_path, props in objs.items():
        if IFACE_GATT_MGR_1 in props.keys() and iface in obj_path:
            return obj_path

    return None


def __test():
    pass


def main():
    global mainloop
    global restart_flag

    while True:
        try:
            # subprocess.run(["sudo", "systemctl", "restart", "bluetooth.service"])
            # time.sleep(2)

            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

            sys_bus = SystemBus()
            root_obj = RootObject(sys_bus)
            mainloop = GObject.MainLoop()

            hci_obj_path = find_gatt_hci_obj_path(sys_bus, 'hci0')
            if not hci_obj_path:
                print(ERROR, 'Interface org.bluez.GattManager1 not found')
                exit(1)
            print(INFO, 'Using', hci_obj_path)


            print(INFO, 'Registering RootObject...')
            gatt_mgr_1_iface = dbus.Interface(
                sys_bus.get_object(BLUEZ_NAME, hci_obj_path), 
                IFACE_GATT_MGR_1
            )
            gatt_mgr_1_iface.RegisterApplication(ObjectPath(root_obj.path), {},
                reply_handler=register_app_callback,
                error_handler=register_app_error_callback)

            def periodic_adv_callback():
                # print(INFO, 'Enable advertising')
                HCI('hci0').le_set_advertising_enable({'Advertising_Enable': 0x01})
                return True # 返回 True 从而继续被回调
            GObject.timeout_add(5000, periodic_adv_callback)
            # print(INFO, 'Enable periodic advertising')
            # event_params = HCI('hci0').le_set_periodic_advertising_enable()
            # print('\t', event_params, sep='')

            print(INFO, 'mainloop', 'run')
            mainloop.run()
            print(INFO, 'mainloop', 'stop')

        except KeyboardInterrupt:
            try:
                gatt_mgr_1_iface.UnregisterApplication(
                    ObjectPath(root_obj.path))
                print(INFO, 'Unregistering RootObject...')
            except DBusException as e:
                print(ERROR, 'UnregisterApplication DBusException')
                mainloop.quit()
                logging.exception(e)
                break
            mainloop.quit()
            break
        except Exception:
            try:
                gatt_mgr_1_iface.UnregisterApplication(
                    ObjectPath(root_obj.path))
                print(INFO, 'Unregistering RootObject...')
            except DBusException as e:
                print(ERROR, 'UnregisterApplication DBusException')
                logging.exception(e)
            mainloop.quit()
        

if __name__ == '__main__':
    main()
