import ubluetooth as bt
from time import sleep

"""
UUIDS:
e1d807c6-6dd4-4345-a744-9c5b492144c1 (THIS ONE)

f5ed34bf-1091-4715-8886-52cb7c606411

3843a27a-1e93-4a1b-a89e-b0e0cef97c50

5bae6c80-d05f-44bd-b093-59b8d4d9aba5
"""

UUID_BE = bytes.fromhex('e1d807c66dd44345a7449c5b492144c1')
UUID_LE = UUID_BE[::-1]
MESSAGE = b"Tractor A"

ble = bt.BLE()
ble.active(True)

def advertise():
    # 1) Flags AD structure
    flags = b'\x02\x01\x06'
    svc_uuid = bytes([len(UUID_LE) + 1, 0x07]) + UUID_LE
    svc_data = bytes([len(UUID_LE) + len(MESSAGE) + 1, 0x21]) + UUID_LE + MESSAGE
    ble.gap_advertise(100_000, flags + svc_uuid + svc_data)

while True:
    print(f"Advertising: {MESSAGE}")
    advertise()
    sleep(1)
