# pynmap
A serious(Tried to be) attempt to implement multi-threading to nmap module, which would result in faster scanning speed. I know that one can write NSE scripts for multi-threaded scanning with it, but I wanted to try it on python.

Usage :
- `python pingsweep.py -t 192.168.1.0/24`


### Changelog
- refactored common classes into lib package
- rewritten pingsweep using python's built-in concurrent module, instead of rolling my own worker threads. This reduced the code into barely 50 lines of code.
- updated the code into python3.5 and above, since type annotations are only available from python3.5 and above.


Result
======
When I first created this repo, nmap scanner I was using (can't remember the version) took about 27 seconds to scan 192.168.1.0/24 range, but this program can do that within 5 seconds. But now, things have changed, and new nmap version 7.70 can do the same in 2.3 seconds. But still, this would be a good experiment to try to beat nmap speed. Maybe write a custom scapy packet generator to scan manually?

![image of result](http://i.imgur.com/Im87Hj0.png)

![image of result](http://i.imgur.com/WZoEJTL.png)

Requirement
===========
python3.5 and above
