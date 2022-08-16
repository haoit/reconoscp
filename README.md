# oscp_autorecon
## Installation

There are three ways to install AutoRecon: pipx, pip, and manually. Before installation using any of these methods, certain requirements need to be fulfilled. If you have not refreshed your apt cache recently, run the following command so you are installing the latest available packages:

```bash
sudo apt update
git clone https://github.com/haoit/reconoscp.git
cd reconoscp && pip3 install -r requirements.txt
```
### Usage
```
└─$ python3 reconoscp.py -h
usage: reconoscp.py [-h] -i IP [-sc SCREENSHOT] -m MODE [-f FILES] [-ef EXTENTIONS]

OSCP Auto Enum

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        IP of target
  -sc SCREENSHOT, --screenshot SCREENSHOT
                        Mode manual screenshot
  -m MODE, --mode MODE  1. Full Enum, 2. Report, 3.Nmap Only, 4.Screenshot
  -f FILES, --files FILES
                        file targer
  -ef EXTENTIONS, --extentions EXTENTIONS
                        Extentions file scan for ffuf
```
