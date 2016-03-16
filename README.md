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

