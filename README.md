XEN Volatility Plugins
======================

Here are modified Volatility executable vol.py for XEN and plugins for XEN core dump and snapshots analysis

Installation
------------

* Replace in Volatility folder original vol.py with vol.py from this repo
* Clone plugins xen_dump.py and xen_snapshot.py to a separate folder. E.G: plugins

Dependencies
------------

Python 2.7
Xen 4.4+
XL Toolstack
libvirt-bin
libvirt-python
volatility

Usage
-----
```
python volatility/vol.py --plugins=<path_to_plugins> --profile=<profile_name> --xendomain <name_of_running_xen_domain> <command>
```

E.G:
```
python volatility/vol.py --plugins=plugins --profile=LinuxArchLinuxx64 --xendomain dom-1 linux_psaux
```
