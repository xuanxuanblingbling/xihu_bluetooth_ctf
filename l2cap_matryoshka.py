#!/usr/bin/env python3

import sys
import struct
import logging

# sys.path.insert(0, '/mnt/hgfs/OneDrive/Projects/bthci/src')
# sys.path.insert(0, '/mnt/hgfs/OneDrive/Projects/pyclui/src')

from bthci import PISCAN
from bthci import HCI
from pyclui import DEBUG

from bluetooth import BluetoothSocket, L2CAP
from bluetooth import advertise_service
from bluetooth.btcommon import BluetoothError

from pyclui import blue, green, yellow, red
from pyclui import DEBUG, INFO, WARNING, ERROR

FLAG = 'flag{br0h1pIt_l@cab_watrx0sHka}'
GET_FLAG_TIP = 'WantGetFlag?SendMeInfoPayload"flag"'

SIGNAL_PKT_HDR_LEN = 4

SIG_CID = 0x0001

L2CAP_INFOMATION_REQ_LEN = 6
L2CAP_CONNECTION_REQ_LEN = 8
L2CAP_CONFIGURATION_REQ_LEN = 8

MIN_L2CAP_COMMAND_REJECT_RSP = 6

L2CAP_INFORMATION_REQ    = 0x0A
L2CAP_INFORMATION_RSP   = 0x0B
L2CAP_CONNECTION_REQ    = 0x02
L2CAP_CONNECTION_RSP    = 0x03
L2CAP_CONFIGURATION_REQ = 0x04
L2CAP_CONFIGURATION_RSP = 0x05

INFO_TYPE_LEN = 2
INFO_TYPES = (0x0001, 0x0002, 0x0003)

class L2CAPMatryoshkaServer:
    def __init__(self):
        self.serv_id = '11111111-2222-3333-4444-555555555555'
        self.serv_name = 'L2CAP Matryoshka'
        self.serv_class_id_list = ['11111111-1111-1111-1111-111111111111']
        self.bt_profile_descp_list = [('22222222-2222-2222-2222-222222222222', 2)]
        self.provider_name = 'Sourcell Xu of HatLab, DBAPP Security'
        self.serv_descp = 'What\'s the innermost part of this L2CAP Matryoshka?'
        self.protocol_descp_list = ['0100', '0100']
        
        self.hci = HCI('hci0')
        self.lis_addr = self.hci.read_bdaddr()['BD_ADDR']
        self.psm = 0x1031
        self.sock = BluetoothSocket(L2CAP)
        self.sock.bind((self.lis_addr, self.psm))

        self.level1_psm = 0x1041
        self.level1_serv_cid = 0x0041
        
        self.level2_psm = 0x1051
        self.level2_serv_cid = 0x0042

        print(DEBUG, 'Server socket name')
        sock_name = self.sock.getsockname()
        print('\t'+sock_name[0])
        print('\t0x%04x'%sock_name[1])

        # print(DEBUG, 'sock opts:', self.sock.getsockopt())
        # print(DEBUG, 'sock timeout:', self.sock.gettimeout())
        # print(DEBUG, 'sock l2cap opts:', self.sock.get_l2cap_options())


    def run(self):
        self.sock.listen(1)
        print(INFO, 'Listening...')

        # PISCAN must be enabled before calling advertise_service()
        self.hci.write_scan_enable({'Scan_Enable':PISCAN})
        advertise_service(self.sock, self.serv_name, self.serv_id, 
            self.serv_class_id_list, self.bt_profile_descp_list, 
            self.provider_name, self.serv_descp, self.protocol_descp_list)
        
        while True:
            print(INFO, 'Accept...')
            self.client_sock, self.client_info = self.sock.accept()
            print(DEBUG, 'Peer socket name')
            client_sock_name = self.client_sock.getpeername()
            print('\t'+client_sock_name[0])
            print('\t0x%04x'%client_sock_name[1])
            print(INFO, 'Accepted connection from %s, PSM 0x%x'%(
                self.client_info[0], self.client_info[1]))
            try:
                self.level0()
                self.level0data_level1signal()
                self.level1data_level2signal()
                self.level2data()
                self.client_sock.close()
            except RuntimeError as e:
                logging.exception(e)
                self.client_sock.close()
            

    def level0(self):
        '''Outermost L2CAP connection'''
        self.client_sock.send(b'Level1:ConnectMe')


    def level0data_level1signal(self):
        '''First nesting'''
        req_flag = False
        conn_flag = False
        conn_tip = 'PSM'+'%04x'%self.level1_psm+'ForConn'

        while True:
            signal_pkt = self.client_sock.recv(1024)
            if len(signal_pkt) == 0:
                raise RuntimeError('len(signal_pkt) == 0')
            elif 0 < len(signal_pkt) < 10 or len(signal_pkt) == 1024:
                # L2CAP_INFOMATION_REQ、L2CAP_CONNECTION_REQ 和 L2CAP_CONFIGURATION_REQ 要求的最小长度为 10
                continue
            
            print(DEBUG, 'level0data_level1signal, recv')
            print('<', signal_pkt)

            try:
                info_payload_len, cid, code, identifier, length = \
                    struct.unpack('<HHBBH', signal_pkt[:SIGNAL_PKT_HDR_LEN+4])
                data = struct.unpack('<%ds'%length, signal_pkt[SIGNAL_PKT_HDR_LEN+4:])[0]
                print('\tinfo_payload_len: 0x%04x'%info_payload_len)
                print('\tCID: 0x%04x'%cid)
                print('\tcode: 0x%02x'%code)
                print('\tidentifier: 0x%02x'%identifier)
                print('\tlength: 0x%04x'%length)
                print('\tdata:', data)
            except struct.error as e:
                logging.exception(e)
                continue

            if info_payload_len != 4 + length or cid != SIG_CID:
                # code、identifier 与 length 的长度加起来为 4
                # print(INFO, 'info_payload_len != 4 + length')
                # print(INFO, 'Failed to pass level 1 L2CAP_INFOMATION')
                continue
            
            if code == L2CAP_INFORMATION_REQ:
                try:
                    info_type = struct.unpack('<H', data)[0]
                    print('\t\tInfoType: 0x%04x'%info_type)
                    self.client_sock.send(struct.pack('<HHBBHHH%ds'%len(conn_tip), 
                        8+len(conn_tip), SIG_CID, L2CAP_INFORMATION_RSP, identifier, 
                        4+len(conn_tip), info_type, 0x0000, conn_tip.encode()))
                    req_flag = True
                    print(INFO, 'Passed level0data_level1signal, L2CAP_INFOMATION')
                except struct.error as e:
                    logging.exception(e)
                    print(INFO, 'Failed to pass level0data_level1signal, L2CAP_INFOMATION')
                    continue
            elif req_flag and code == L2CAP_CONNECTION_REQ:
                try:
                    psm, scid = struct.unpack('<HH', data)
                    print('\t\tPSM: 0x%04x'%psm)
                    print('\t\tSCID: 0x%04x'%scid)
                except struct.error as e:
                    logging.exception(e)
                    print(INFO, 'Failed to pass level0data_level1signal, L2CAP_CONNECTION')
                    continue

                if psm == self.level1_psm and 0x0040 <= scid <= 0xffff:
                    self.level1_client_cid = scid
                    self.client_sock.send(struct.pack('<HHBBHHHHH', 
                        12, SIG_CID, L2CAP_CONNECTION_RSP, identifier, 
                        8, self.level1_serv_cid, self.level1_client_cid, 0x0000, 0x0000))
                    conn_flag = True
                    print(INFO, 'Passed level0data_level1signal, L2CAP_CONNECTION')
                else:
                    print(INFO, 'Failed to pass level0data_level1signal, L2CAP_CONNECTION')
            elif req_flag and conn_flag and code == L2CAP_CONFIGURATION_REQ:
                try:
                    dcid, flags, config_opts = struct.unpack('HH%ds'%(length-4), data)
                    print('\t\tDCID: 0x%04x'%dcid)
                    print('\t\tflags: 0x%04x'%flags)
                    print('\t\tconfig_opts:', config_opts)
                    if dcid == self.level1_serv_cid and flags & 0xFFF0 == 0:
                        self.client_sock.send(struct.pack('<HHBBHHHH', 
                            10, SIG_CID, L2CAP_CONFIGURATION_RSP, identifier, 
                            6, self.level1_client_cid, 0x0000, 0x0000))
                        print(INFO, 'Passed level0data_level1signal, L2CAP_CONFIGURATION')
                        return
                    else:
                        print(INFO, 'Failed to pass level0data_level1signal, L2CAP_CONFIGURATION')
                except struct.error as e:
                    logging.exception(e)
                    print(INFO, 'Failed to pass level0data_level1signal, L2CAP_CONFIGURATION')
            else:
                print(INFO, 'Invalid code')


    def level1data_level2signal(self):
        req_flag = False
        conn_flag = False
        start_tip = 'Level1:Passed,Level2:ConnectMe'
        conn_tip = 'PSM'+'%04x'%self.level2_psm+'ForConn'

        self.client_sock.send(struct.pack('<HH%ds'%len(start_tip), 
            len(start_tip), self.level1_client_cid, start_tip.encode()))

        while True:
            b_frame = self.client_sock.recv(1024)
            if len(b_frame) == 0:
                raise RuntimeError('len(b_frame) == 0')
            elif len(b_frame) < 14 or len(b_frame) == 1024:
                # B-frame 封装 L2CAP_INFOMATION_REQ、L2CAP_CONNECTION_REQ 或 L2CAP_CONFIGURATION_REQ 后，最小长度为 14
                continue

            print(DEBUG, 'level1data_level2signal, recv')
            print('<', b_frame)

            try:
                info_payload_len, cid = struct.unpack('<HH', b_frame[:4])
                signal_pkt = struct.unpack('%ds'%info_payload_len, b_frame[4:])[0]
                if cid != self.level1_serv_cid or info_payload_len < 10:
                    # L2CAP_INFOMATION_REQ、L2CAP_CONNECTION_REQ 和 L2CAP_CONFIGURATION_REQ 要求的最小长度为 10
                    continue
            except struct.error as e:
                logging.exception(e)
                continue
            
            try:
                info_payload_len, cid, code, identifier, length = \
                    struct.unpack('<HHBBH', signal_pkt[:SIGNAL_PKT_HDR_LEN+4])
                data = struct.unpack('<%ds'%length, signal_pkt[SIGNAL_PKT_HDR_LEN+4:])[0]
                print('\tinfo_payload_len: 0x%04x'%info_payload_len)
                print('\tCID: 0x%04x'%cid)
                print('\tcode: 0x%02x'%code)
                print('\tidentifier: 0x%02x'%identifier)
                print('\tlength: 0x%04x'%length)
                print('\tdata:', data)
            except struct.error as e:
                logging.exception(e)
                continue

            if info_payload_len != 4 + length or cid != SIG_CID:
                # code、identifier 与 length 的长度加起来为 4
                # print(INFO, 'info_payload_len != 4 + length')
                # print(INFO, 'Failed to pass level 2 L2CAP_INFOMATION')
                continue
            
            if code == L2CAP_INFORMATION_REQ:
                try:
                    info_type = struct.unpack('<H', data)[0]
                    print('\t\tInfoType: 0x%04x'%info_type)
                    self.client_sock.send(struct.pack('<HHHHBBHHH%ds'%len(conn_tip), 
                        12+len(conn_tip), self.level1_client_cid, 
                        8+len(conn_tip), SIG_CID, L2CAP_INFORMATION_RSP, identifier, 
                        4+len(conn_tip), info_type, 0x0000, conn_tip.encode()))
                    req_flag = True
                    print(INFO, 'Passed level1data_level2signal, L2CAP_INFOMATION')
                except struct.error as e:
                    logging.exception(e)
                    print(INFO, 'Failed to pass level1data_level2signal, L2CAP_INFOMATION')
                    continue
            elif req_flag and code == L2CAP_CONNECTION_REQ:
                try:
                    psm, scid = struct.unpack('<HH', data)
                    print('\t\tPSM: 0x%04x'%psm)
                    print('\t\tSCID: 0x%04x'%scid)
                except struct.error as e:
                    logging.exception(e)
                    print(INFO, 'Failed to pass level1data_level2signal, L2CAP_CONNECTION')
                    continue

                if psm == self.level2_psm and 0x0040 <= scid <= 0xffff:
                    self.level2_client_cid = scid
                    self.client_sock.send(struct.pack('<HHHHBBHHHHH', 
                        16, self.level1_client_cid, 
                        12, SIG_CID, L2CAP_CONNECTION_RSP, identifier, 
                        8, self.level2_serv_cid, self.level2_client_cid, 0x0000, 0x0000))
                    conn_flag = True
                    print(INFO, 'Passed level1data_level2signal, L2CAP_CONNECTION')
                else:
                    print(INFO, 'Failed to pass level1data_level2signal, L2CAP_CONNECTION')
            elif req_flag and conn_flag and code == L2CAP_CONFIGURATION_REQ:
                try:
                    dcid, flags, config_opts = struct.unpack('HH%ds'%(length-4), data)
                    print('\t\tDCID: 0x%04x'%dcid)
                    print('\t\tflags: 0x%04x'%flags)
                    print('\t\tconfig_opts:', config_opts)
                    if dcid == self.level2_serv_cid and flags & 0xFFF0 == 0:
                        self.client_sock.send(struct.pack('<HHHHBBHHHH', 
                            14, self.level1_client_cid, 
                            10, SIG_CID, L2CAP_CONFIGURATION_RSP, identifier, 
                            6, self.level1_client_cid, 0x0000, 0x0000))
                        print(INFO, 'Passed level1data_level2signal, L2CAP_CONFIGURATION')
                        return
                    else:
                        print(INFO, 'Failed to pass level1data_level2signal, L2CAP_CONFIGURATION')
                except struct.error as e:
                    logging.exception(e)
                    print(INFO, 'Failed to pass level1data_level2signal, L2CAP_CONFIGURATION')
                    continue 
            else:
                print(INFO, 'Invalid code')


    def level2data(self):
        self.client_sock.send(struct.pack('<HHHH%ds'%len(GET_FLAG_TIP), 
            4+len(GET_FLAG_TIP), self.level1_client_cid, 
            len(GET_FLAG_TIP), self.level2_client_cid, GET_FLAG_TIP.encode()))

        while True:
            b_frame = self.client_sock.recv(1024)
            if len(b_frame) == 0:
                raise RuntimeError('level 3, len(b_frame) == 0')
            if len(b_frame) != 12:
                continue

            try:
                info_payload_len1, cid1, info_payload_len2, cid2, payload2 = struct.unpack('<HHHH4s', b_frame)
                print('info_payload_len1:', info_payload_len1)
                print('CID1:', cid1)
                print('info_payload_len2:', info_payload_len2)
                print('CID2:', cid2)
                print('payload2:', payload2)

                if info_payload_len1 == 8 and cid1 == self.level1_serv_cid \
                   and info_payload_len2 == 4 and cid2 == self.level2_serv_cid \
                   and payload2 == b'flag':
                    self.client_sock.send(struct.pack('<HHHH%ds'%len(FLAG), 
                        4+len(FLAG), self.level1_client_cid, 
                        len(FLAG), self.level2_client_cid, FLAG.encode()))
                    return
                else:
                    self.client_sock.send(
                        struct.pack('<HHHH%ds'%len(GET_FLAG_TIP), 
                            4+len(GET_FLAG_TIP), self.level1_client_cid, 
                            len(GET_FLAG_TIP), self.level2_client_cid, 
                            GET_FLAG_TIP.encode()))
            except struct.error as e:
                logging.exception(e)
                print(INFO, 'Failed to pass level2data')


def __test():
    pass


def main():
    L2CAPMatryoshkaServer().run()


if __name__ == "__main__":
    main()
