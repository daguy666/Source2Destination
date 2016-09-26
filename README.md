# Source2Destination


S2D is a script that will finger print hardware on your network as well as geo lookups on the ip addresses. 

The following dependancies are required:

- [Scapy](http://www.secdev.org/projects/scapy/) 
- [Pygeoip](https://pypi.python.org/pypi/pygeoip/)
- [Netaddr](https://pypi.python.org/pypi/netaddr)

The GeoLookup Database is hardcoded to live in the following directory.
```
'/usr/local/geo/GeoLiteCity.dat'
```
That dat file can be downloaded from the [MaxMind Site](http://dev.maxmind.com/geoip/legacy/geolite/)


Usage of this script: 

```
sudo ./S2D.py <interface> <number of packets to capture> 
```

Exmaple of some oputput: 

```
sudo ./S2D.py en0 4

[*] Capturing 5 packets to analyze on interface en0 ...
Timestamp="09/26/2016 00:09:35" Protocol="TCP" Source="<ip_address>" Location="United States, VA" Source Mac="<mac_address>" HW_Vendor="Actiontec Electronics, Inc" Destination="<ip_address>" Location="Unregistered" Destination Mac="<mac_address>"HW_Vendor="Apple"
Timestamp="09/26/2016 00:09:35" Protocol="TCP" Source="<ip_address>" Location="Unregistered" Source Mac="<mac_address>" HW_Vendor="Apple" Destination="<ip_address>" Location="United States, VA" Destination Mac="<mac_address>" HW_Vendor="Actiontec Electronics, Inc"
Timestamp="09/26/2016 00:09:35" Protocol="TCP" Source="<ip_address>" Location="United States, VA" Source Mac="<mac_address>" HW_Vendor="Actiontec Electronics, Inc" Destination="<ip_address>" Location="Unregistered" Destination Mac="<mac_address>" HW_Vendor="Apple"
Timestamp="09/26/2016 00:09:35" Protocol="TCP" Source="<ip_address>" Location="United States, VA" Source Mac="<mac_address>" HW_Vendor="Actiontec Electronics, Inc" Destination="<ip_address>" Location="Unregistered" Destination Mac="<mac_address>" HW_Vendor="Apple"
```


Adjust these options depending on how you want the script to output. 

- Log to file? set ```self.log = True```
- print to stdout? set ```self.print_to_screen = True```
- Both? set them both to ```True```

*Define your log file and path here.*

```
LOG2FILE = logging.FileHandler('network.log')
```

```python
class Inspect_Traffic(object):

  def __init__(self):
    <snip>
    self.log             = False
    self.print_to_screen = True
    </snip>
```    
