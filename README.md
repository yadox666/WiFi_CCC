Wi-Fi Covert Channel Chat
----------------------------------------------
(Ultra secret chat using Wi-Fi covert channel)
Author: Yago F. Hansen - 2017

Covert Channel [Wikipedia]: a covert channel is a type of computer security attack that creates 
a capability to transfer information objects between processes that are not supposed to be allowed 
to communicate by the computer security policy.

Today, in a world where the hacking techniques are getting more and more sophisticated and security 
measures are growing up to fight against them in a form of firewalls, sensors, interceptors, DPI… 
the hackers have to be more creative in order to develop new methods to exfiltrate data from secured 
facilities. Data exfiltration defines the act of extracting and transferring information from computer 
systems without authorization of the owners. During the last years, data exfiltration has grown by the 
use of covert channels techniques, like using know protocols as DNS, ICMP or using power consumption 
monitoring, glitch analysis, RF emission, etc. All these ways are used to exfiltrate information or 
to command and control devices remotely.

For this speech, I present another method for bypassing well known protocols as 802.11 (Wi-Fi), 
modifying its packet structure to fool drivers and protocol handlers, in a way they will ignore or discard 
this kind of malformed packets avoiding security detection or analysis of this communications. 

To demonstrate these abilities, this Chat application (using Python Programming language in 
combination with Scapy packet handling library) that creates a kind of covert channel using 802.11 packets. 


Usage:
------
The usage of this chat is very simple: 

1. just connect a monitor mode Wi-Fi card that supports traffic injection capabilities, 
2. execute by typing: python wifichat.py
3. the script will ask for a nick name or alias 
4. the script will ask for the secret IRC room name. 

Based just on this name, the Wi-Fi card sets on a specific channel, sets a destination MAC address 
and initializes an AES symmetric key for the encryption of this virtual room. Every user that knows 
this secret room name will be in the same room, being notified about the actual users in the IRC room. 

All the users will work also as Wi-Fi repeaters to increase the signal between nodes. It's also possible 
to send files or pictures to anyone. Users can create so many rooms as needed, creating so a small 
infrastructure inside a building. 

Internally, the script creates malformed 802.11 packets that are usually silently discarded by standard 
Wi-Fi cards (this improves also security).


Commands:
---------
Just write your message and press enter to send!
or you can use following commands:

:ping:         - ping all the other nodes (test)

:usrs:         - show all the detected users

:file:filename - send a file to all the users

:cmmd:command  - execute local command and send result

:exit:         - exit (press Ctrl+C if you are a pro!)

