# ReadMe


## Prerequisites
In order to run the application on the system the following needs to be installed:
- Python 2.7 needs to be installed on the system
- Python library Scapy needs to be installed on the system

Without installing the above mentioned modules the application will not be able to run.

## Installing
In order to run the application Github repository should be cloned to a directory chosen by the user. No other steps are required. Python can be downloaded from: [Download Python](https://www.python.org/downloads/)
Pip can be used through the command prompt to install the required library. Pip comes standard with installing Python.

## Execution
To execute the application a terminal will have to be opened. This terminal should be navigated to the directory where the Github repository was cloned into. Once navigated to correct directory the application can be launched with the following command:
```  
Sudo python main.py [mode_of_attack] [sleep_time]  
```
Where ```[mode_of_attack]``` should be filled in with either ```arp``` or ```dns``` depending on which attack should be performed. ```[sleep_time]``` should be filled with a value in seconds which is desired to be between each packet re-arping the ARP table, for example ```5.0```.

AUTHORS: Andrei Agaronian, Thorn Jansen
