import ubluetooth as bt
from time import sleep
from machine import I2C, Pin
from ina219_lib import INA219
from adc_sub import ADC_substitute

i2c_port = 0
ina219_addr = 0x40
i2c = I2C(i2c_port, sda=Pin(18), scl=Pin(19), freq=400_000)
ina219 = INA219(i2c, ina219_addr)

raw_adc = ADC_substitute(Pin(34))

"2437"
"1692"

a = (100 - 0) / (2380 - 1688)
b = 0 - (a * 1688)

led = Pin(17, Pin.OUT)
led.value(1)

def percentage():
    adc_value = raw_adc.read_adc()
    
    pct = a * adc_value + b
    
    if pct > 100:
        pct = 100
    elif pct < 0:
        pct = 0
    
    return int(round(pct, 0))

"""
UUIDS:
e1d807c6-6dd4-4345-a744-9c5b492144c1 (THIS ONE)

f5ed34bf-1091-4715-8886-52cb7c606411

3843a27a-1e93-4a1b-a89e-b0e0cef97c50

5bae6c80-d05f-44bd-b093-59b8d4d9aba5
"""

UUID_BE = bytes.fromhex('e1d807c66dd44345a7449c5b492144c1')
UUID_LE = bytes(reversed(UUID_BE))

ble = bt.BLE()
ble.active(True)

def life():
    current = ina219.get_current()
    
    time = 1800 / current
    
    if time < 0:
        time = 0
    
    return round(time, 2)

def advertise(message):
    # 1) Flags AD structure
    flags = b'\x02\x01\x06'
    
    svc_uuid = bytes([len(UUID_LE) + 1, 0x07]) + UUID_LE
    adv_data = flags + svc_uuid
    
    scan_resp = bytes([len(message) + 1, 0x09]) + message
    
    ble.gap_advertise(100_000, adv_data=adv_data, resp_data=scan_resp)
    
while True:
    time = life()
    pct = percentage()
    
    msg = f"Tractor A|{time}h|{pct}%"
    bmsg = bytes(msg, "utf-8")
    advertise(bmsg)
    
    print(f"Advertising: {bmsg}%")
    
    sleep(1)
