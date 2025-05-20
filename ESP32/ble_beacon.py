# Will only work on an ESP32 with MicroPython
import ubluetooth as bt, struct, time
from micropython import const

ble = bt.BLE()
ble.active(True)

EDDYSTONE_UUID = const(0xFEAA)
FRAME_TYPE_UID = b'\x00'
NAMESPACE      = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A'
INSTANCE       = b'HELLO!'    # 6 bytes
TX_POWER       = b'\xd7'      # -41 dBm

def advertise():
    # 1) Flags AD structure
    flags = b'\x02\x01\x06'
    svc = (
      bytes([len(FRAME_TYPE_UID + NAMESPACE + INSTANCE + TX_POWER) + 3, 0x16])
      + struct.pack("<H", EDDYSTONE_UUID)
      + FRAME_TYPE_UID + TX_POWER + NAMESPACE + INSTANCE
    )
    ble.gap_advertise(100_000, flags + svc)

while True:
    print(f"Advertising: {INSTANCE}")
    advertise()
    time.sleep(1)
