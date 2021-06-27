#!/usr/bin/env python3

import sys
import base64
from pyclui import DEBUG

# sys.path.insert(0, '/mnt/hgfs/OneDrive/Projects/bthci/src')
# print(sys.path)

from bthci import HCI

FLAG = 'ble@e_b5p@k_fl@go!'

flag_base64 = base64.b64encode(FLAG.encode())
# print(DEBUG, flag_base64)
# exit(0)


def __test():
    pass


def main():
    pass


if __name__ == '__main__':
    hci = HCI('hci0')

    hci.le_set_advertising_parameters({
        'Advertising_Interval_Min': 0x0800, 
        'Advertising_Interval_Max': 0x0800,
        'Advertising_Type': 0x00, # 
        'Own_Address_Type': 0x00, # Public Device Address 
        'Peer_Address_Type': 0x00, #
        'Peer_Address': bytes(6),
        'Advertising_Channel_Map': 0x07,
        'Advertising_Filter_Policy': 0x00})


    adv_data = b'\x0b\xFE' + flag_base64[14:24] + \
        b'\x0b\xFD' + flag_base64[4:14] + \
        b'\x05\xFC' + flag_base64[:4]
        # b'\x05\x04' + \
        # b'\x05\x05' + \
        # b'\x05\x06' + \
        # b'\x05\x07' + \
    hci.le_set_advertising_data({
        'Advertising_Data_Length': len(adv_data),
        'Advertising_Data': adv_data + b'\x00'})

    hci.le_set_advertising_enable({
        'Advertising_Enable': 0x01
    })

