# GIRA(GUI for Important Registry artifacts)


GIRA is a forensic tool. It will help in easy access of registry artifact information. This tool is still in development and please feel free to make modifications and suggest.


# GIRA Features!

  - # USB's Connected
      List of USB devices connected to the machine. As of now, only names are displayed. future version will include unique identifier. 
  - # Installed Applications
      List of installed application in the system. this information is retreived from uninstall apps list.
  - # Recent Files
      List of recently used files by the particular user in the order of Latest to Oldest(This feature requires some time & a little buggy yet works!)
  - # Last Edited Registry Information
      Latest edited registry hive is shown here.
  - # Window's Information
      This displays Current Build number, System Directory, Owner, OS Installed
  - # Startup Apps
      List of apps that are added to default startup. 
  - # Last RUN Command
      Latest RUN command that is run even before a reboot.
  - # IP Information
      List of IP's this system got a=ssigned with and their lease period.
  - # System Information
      This window shows the system proccessor information
  - # USER's Information
      List of USER's Registered on the system.

GIRA is in it's introduction stage and can sometimes be *extremely buggy*. Please feel free to raise issues or contribute to this repo.

### Tech

GIRA uses a number of open source projects to work properly:

* [PyQt5](https://pypi.org/project/PyQt5/) - Python GUI designer.
* [winreg](https://docs.python.org/3/library/winreg.html) - Windows registry parser.
* [tabulate](https://pypi.org/project/tabulate/) - To enrich text output into table formats.

### Installation

Dillinger requires [python3](https://www.python.org/download/releases/3.0/) v3+ to run.

Install the dependencies.

```sh
$ pip install PyQt5
$ pip install tabulate
```

### RUN

Make sure you run this with python v3

```sh
$ python GIRA.py
