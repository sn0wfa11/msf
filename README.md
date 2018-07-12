# sn0wfa11's Collection of Personal Metasploit Modules, Plugins, and Modifications

This repository contains many of my Metasploit modules, plugins, and personal modifications. 

They are included here for various reasons:
- Testing in preperation for submission to the Metasploit-Framework Project
- Is outside of the requirements for submission to the MSF Project. (ie. Modules that call other modules.)
- Is my own take on a module that is already in the framework.
- Is a plugin or modification that I like to use, but that the MSF Project might not want to include for various reasons. Keep in mind that the MSF project has to account for many different things such as how a modification might interact with their Windows or Pro versions. I don't have to worry about that since I'm using Kali and the free framework.

I welcome suggestions or pull requests to anything include here, but keep in mind the below disclamer.

**New Additions:**
- I added two modules to exploit EternalBlue. These are optimizations of the modules currently included in the Metasploit Framework. I was able to get the exploits to run without the need for specifying an open share. I also added the 'check' ability to the module under `exploits/windows`. The `auxiliary` module is a modification of the run command module. It was modified to download and run a file such as a .bat file. This works very well for using Veil payloads... Both are tested and work correctly against unpatched Server 2012R2.
- Linux priv_check now supports running Linux Exploit Suggester as part of its tests. Give it a path to LES, a writable directory on the target and set the LES flag to true. 

**Disclamer**: Any module, plugin, or modification included in this repository is provided with no support, no guarantee that it will work, and is use at your own risk. I take no responcibility for illegal or improper use of anything provided here. All code is open source. 

**Under Construction**

Look for my Overwatch MSF plugin.

Added a Linux Privilege Escalation Check module to modules/post/linux. Check it out! Still working on adding a kernel exploit suggester to that module. A Windows version will be coming soon!
