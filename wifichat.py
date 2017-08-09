#!/usr/bin/python
# -*- coding: utf-8 -*-​
# to-do: send files (receive in sync order and with integrity)
import threading, time, sys, base64, logging, subprocess
import textwrap
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from threading import Thread
from datetime import datetime
from random import randint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 

# User defined variables
verbose=0  ## debug level (1-3)
pcount=6  ## number of packet 
repeater=0  ## act also as repeater of other nodes
history=1  ## remember commands
defaultinterface='wlan1'  

# System variables
maxpayload=258
sc=randint(1,1024)
lastpacketsc=[]
userlist={}
bootime=time.time()
pktcount=0
pktcounts=0
pktcountw=0
pktcountpb=0
pktcountpbd=0
pingcount=0
pingsc=[]
broadcast='ff:ff:ff:ff:ff:ff'

## InitMon: function to initialize monitor mode vif
def InitMon(interface):
    global intfmon
    if not os.path.isdir("/sys/class/net/" + interface):
        logging.error("WiFi parent interface %s does not exist! Cannot continue!" %interface)
        return False
    else:
        intfmon = 'mon' + interface[-1]
        if os.path.isdir("/sys/class/net/" + intfmon):
            if verbose > 1: logging.debug('DEBUG', 33, "WiFi interface %s exists! Deleting it!" % (intfmon))
            try:
                os.system("iw dev %s del" % intfmon)
                time.sleep(0.3)
            except OSError as e:
                logging.error("Could not delete monitor interface %s" % intfmon)
                os.kill(os.getpid(), SIGINT)
                return False
        try:
            # create monitor interface using iw
            os.system("iw dev %s interface add %s type monitor" % (interface, intfmon))
            time.sleep(0.2)
            os.system("rfkill block %s" %interface[-1])
            time.sleep(0.2)
            os.system("ifconfig %s down" %interface)
            time.sleep(0.2)
            os.system("iwconfig %s mode monitor" %interface)
            time.sleep(0.2)
            os.system("rfkill unblock %s" %interface[-1])
            time.sleep(0.2)
            os.system("ifconfig %s up" %interface)
            if verbose > 1: logging.debug("Creating monitor VAP %s for parent %s..." %(intfmon, interface))
        except OsError as e:
            logging.error("Could not create monitor %s" % intfmon)
            os.kill(os.getpid(), SIGINT)
            return False
	return True


## encrypt: function to base64 encode and encrypt user, command and message
def encrypt(user,command,message):
	global maxpayload

	# Cipher and encode user
	padd = len(user) % 16
        if padd > 0: user = user + (' ' * (16 - padd))
        encoded_user = base64.b64encode(cipher.encrypt(user))

	# Cipher and encode command
	padd = len(command) % 16
        if padd > 0: command = command + (' ' * (16 - padd))
        encoded_command = base64.b64encode(cipher.encrypt(command))

	# Cipher and encode message
	padd = len(message) % 16
        if padd > 0: message = message + (' ' * (16 - padd))
        encoded_message = base64.b64encode(cipher.encrypt(message))

	# Calculate total packet length
	cipheredsize = len(encoded_user)+len(encoded_command)+len(encoded_message)
	packetsize = 48 
	chunksize = maxpayload - cipheredsize - packetsize

	return encoded_user,encoded_command,encoded_message,chunksize
	

## chatcrypt: function to cut payload in max size parts, cipher and encode each part
def chatcrypt(payload,chunksize):
	parts=set()
	if len(payload) > chunksize:
	        parts = textwrap.wrap(payload, chunksize)
	else:
		parts.add(payload)

        encoded_parts=set()
        for part in parts:
                lastpadd = len(part) % 16
                if lastpadd > 0: part = part + (' ' * (16 - lastpadd))
                encoded_part = base64.b64encode(cipher.encrypt(part))
                encoded_parts.add(encoded_part)
        return encoded_parts


## filecrypt: function to split files in small parts and encrypt them
def filecrypt(filename,chunksize):
	try:
		with open(filename, mode='rb') as payload:
			fileContent = payload.read()
	except:
		fileContent=''
		print ":chat: cannot open requested file: %s" %filename
		return ''
	try:
		parts = textwrap.wrap(fileContent, chunksize)
		encoded_parts=set()
		for part in parts:
			lastpadd = len(part) % 16
			if lastpadd > 0:
				part = part + ("~" * (16 - lastpadd))
			encoded_part = base64.b64encode(cipher.encrypt(part))
			encoded_parts.add(encoded_part)
		return encoded_parts
	except Exception as e:
		print ":chat: error disecting file: %s. %s" %(filename, e.message)
		return ''

## cmdcrypt: function to execute shell command, split output in parts and encrypt them 
def cmdcrypt(execute,chunksize):
	try:
		execsplit = execute.split(" ")
		p = subprocess.Popen(execsplit, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = p.communicate()
		parts = out.rstrip("\n")
		parts = parts.splitlines() 
		encoded_parts=set()
		for part in parts:
			print ":chat: executed [%s] -> %s" %(execute, part)
			lastpadd = len(part) % 16
			if lastpadd > 0: part = part + (' ' * (16 - lastpadd))
			encoded_part = base64.b64encode(cipher.encrypt(part))
			encoded_parts.add(encoded_part)
		return encoded_parts
	except:
		return ''

## decrypt: function to decrypt received packet fields and return them as a list
def decrypt(user,command,message,payload):
	try:
		dec_user = cipher.decrypt(base64.b64decode(user)).strip()
		dec_command = cipher.decrypt(base64.b64decode(command)).strip()
		dec_message = cipher.decrypt(base64.b64decode(message)).strip()
		dec_payload = cipher.decrypt(base64.b64decode(payload)).strip()
		return dec_user,'',dec_command,dec_message,dec_payload,True
	except:
		return '','','','','',False


## packetSniffer: function to keep sniffing for chat packets and process them when received using packethandler 
def packetSniffer():
	try:
		sniff(iface=intfmon, prn=PacketHandler, store=False, lfilter=lambda pkt: (Dot11ProbeReq in pkt))
	except Exception as e:
		print "Error starting sniffer! %s" %e.message
		exit()


## PacketHandler: function to proccess received packets if related to chat
def PacketHandler(pkt):
	global lastpacketsc,pktcount,pktcountpb, pktcountpbd, pktcountw, pingcount,pingsc
	pktcount += 1
	
	if pkt.addr3.upper() == remote:
		try:
			elt = pkt[Dot11Elt]
			usr=command=message=payload=''
			psc = str(pkt.SC)
			while isinstance(elt, Dot11Elt):
				if elt.ID == 51:  ## AP Channel report
					uuid=elt.info
				elif elt.ID == 7:  ## 7 country
					ciphereduser=elt.info  ## ciphered user
					if (ciphereduser+psc) in lastpacketsc: 
						pktcountpbd += 1
						if verbose > 1: print "Packet discarded: %s" %(ciphereduser)
						return  ## silently discard packet, processed before
				elif elt.ID == 16:  ## meassurement transmission
					cipheredcommand=elt.info
				elif elt.ID == 221:  ## vendor/WPS
					cipheredpayload=elt.info
				elif elt.ID == 66:  ## extended rates 
					cipheredmessage=elt.info
				elt = elt.payload
 
			if verbose > 1: print "Received (encrypted): %s,%s,%s,%s" %(ciphereduser,cipheredcommand,cipheredmessage,cipheredpayload)

			pktcountpb += 1
			decrypted = decrypt(ciphereduser,cipheredcommand,cipheredmessage,cipheredpayload)
			decrypteduser = decrypted[0]
			decryptedcommand = decrypted[2]
			decryptedmessage = decrypted[3]
			decryptedpayload = decrypted[4]
			decryptedok = decrypted[5] ## last field is checksum
			if verbose > 1: print decrypted
			if verbose > 1: print "Received (decrypted): %s,%s,%s,%s" %(decrypteduser,decryptedcommand,decryptedmessage,decryptedpayload)

			if not decryptedok:
				if verbose: print "Malformed packet received!"
				return

			# Add user, if new, to the discovered users dictionary
		        if not userlist.has_key(uuid): userlist[uuid]=decrypteduser

			# Show results of received packet
			pktcountw =+ 1
			if decryptedcommand[:6] == ':msgs:': 
				print "%s: %s" %(decrypteduser, decryptedpayload)
			elif decryptedcommand[:6] == ':ping:':
				if not psc+decrypteduser in pingsc:
					pingsc.append(psc+decrypteduser)
					pingcount=0
					print ""
				pingcount += 1
				sys.stdout.write("\033[F") # Cursor up one line
				print "chat: %d/%s ping packets received from %s!" %(pingcount,decryptedmessage,decrypteduser)
			elif decryptedcommand[:6] == ':cmmd:': 
				print "%s: executed [%s] -> %s" %(decrypteduser, decryptedmessage, decryptedpayload)
			elif decryptedcommand[:6] == ':chat:':
				print "chat: %s" %decryptedpayload
			elif decryptedcommand[:6] == ':file:':
				print "chat: file received [%s] -> %s" %(decryptedmessage,decryptedpayload[:8])
			else:
				print "(%s) %s[%s]: (%s) %s" %(psc,decrypteduser,decryptedcommand,decryptedmessage,decryptedpayload)

			if not decryptedcommand[:6] == ':ping:': 
				lastpacketsc.append(ciphereduser+psc)
			else:
				return

		except Exception as e:
			print e.message

		try:
			# Resend packet for the first time as a repeater if packet is not ours
			if repeater: 
				if verbose: print "Repeating packet %s of user %s to the air" %(psc,decrypteduser)
				sendp(pkt, iface=intfmon, verbose=0, count=pcount)
		except:
			pass 
		return
			

## PacketProcessSend: function to process user commands
def PacketProcessSend(chat):
	global username,sc,histfile
	user=username.strip()
	command = chat[:6]
	message = chat[6:]

	if command == ':chat:':
		encrypted = encrypt(user,command,message)
		chunksize = encrypted[3]
		payload=chatcrypt(message,chunksize)
	        if verbose > 1: print "chat: %s" %(chat[6:])
		if verbose > 2: print encrypted
		PacketSend(encrypted,payload)
	elif command == ':file:':
		encrypted = encrypt(user,command,message)
		chunksize = encrypted[3]
		payload=filecrypt(message,chunksize)
		if verbose > 1: print encrypted
	        print "chat: sending file %s" %message
		PacketSend(encrypted,payload)
	elif command == ':cmmd:': 
		encrypted = encrypt(user,command,message)
		chunksize = encrypted[3]
	        print "chat: executing command %s" %message
		if verbose > 2: print encrypted
		payload=cmdcrypt(message,chunksize)
		PacketSend(encrypted,payload)
	elif command == ':usrs:':
		print "chat: detected users: ",
		for useruuid,usr in userlist.items():
			print "%s(%s)" %(usr,useruuid),
		print ""
	elif command == ':ping:':
		message = str(pcount)
		encrypted = encrypt(user,command,message)
		chunksize = encrypted[3]
		payload = chatcrypt(chat,chunksize)
		if verbose > 2: print encrypted
	        print "chat: sending %d ping packets..." %(pcount)  ## investigate why *5
		PacketSend(encrypted,payload)
	else:
		command = ':msgs:'
		encrypted = encrypt(user,command,message)
		chunksize = encrypted[3]
		payload = chatcrypt(chat,chunksize)
		if verbose > 2: print encrypted
	        print "me: %s" %(chat)
		PacketSend(encrypted,payload)


## PacketSend: function to construct the packet to be sent
def PacketSend(encrypted,payload):
	global uuid,sc,lastpacketsc,pktcounts
	for part in payload: # ojo - revisar
		sc = next_sc()     ## Update sequence number
		if verbose > 1: print "\nsc:%s" %sc
		user=encrypted[0]
		command=encrypted[1]
		message=encrypted[2]
		payload=part
		ds="\x01"
		rates="x98\x24\xb0\x48\x60\x6c"

		# Forge Dot11packet
		dot11 = Dot11(type=0,subtype=4,addr1=broadcast, addr2=RandMAC(),addr3=remote)
		eltessid = Dot11Elt(ID=0,len=0,info='')
		eltrates = Dot11Elt(ID=1,len=len(rates),info=rates)
		eltchannel = Dot11Elt(ID=3,len=1,info=chr(channel))
		eltuser = Dot11Elt(ID=7,len=len(user),info=user) ## country
		eltuuid = Dot11Elt(ID=51,len=len(uuid),info=uuid) ## ap channel report
		eltcommand = Dot11Elt(ID=16,len=len(command),info=command)  ## meassurement transmission
		eltmessage = Dot11Elt(ID=66,len=len(message),info=message) ## extended rates
		eltpayload = Dot11Elt(ID=221,len=len(payload),info=payload) ## vendor/WPS
		dsset = Dot11Elt(ID='DSset',len=len(ds),info=ds)
		pkt = RadioTap()/dot11/Dot11ProbeReq()/eltessid/eltrates/eltchannel/eltpayload/eltuuid/eltuser/eltcommand/eltmessage/dsset
		pkt.SC = sc    ## Update sequence number
		lastpacketsc.append(user+str(sc))   ## Save this packet to not repeat showing it
		#pkt.show()
		if verbose > 1: print "Sent: %s,%s,%s,%s" %(user,command,message,payload)

		try:
			sendp(pkt, iface=intfmon, verbose=0, count=pcount)  ## Send packet several times
			if verbose: print "Packet sent: %s" %(user)
			pktcounts += 1
		except Exception as e:
			print "Cannot send packet! %s" %e.message
	
def current_timestamp():
        global bootime
        return (time.time() - bootime) * 1000000


def next_sc():
        global sc
        sc = (sc + 1) % 4096
        # return sc * 16  # Fragment number -> right 4 bits
        return sc


def md5(message):
    hash = MD5.new()
    hash.update(message)
    return hash.hexdigest()


def getmac(interface):
  try:
    mac = open('/sys/class/net/'+interface+'/address').readline()
  except:
    mac = "00:00:00:00:00:00"
  return mac[0:17]


def SetChannel(channel):
        cmd0 = 'ifconfig %s up >/dev/null 2>&1' % (intfmon)
        cmd1 = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
        try:
                os.system(cmd0)
                os.system(cmd1)
	        print "Setting %s to channel: %s and MAC: %s" %(intfmon,channel,remote)
        except:
		print "Error setting channel for %s" %intfmon


def cleanexit():
	try:
	    PacketProcessSend(":chat:%s left the chat room: %s!" %(username, privateircname)) ## User lefts group
	    readline.write_history_file(histfile)
	    sys.stdout.write("\033[F") # Cursor up one line
	    print "total packets:%s / processed:%s / written:%s / discarded:%s / sent: %s" %(pktcount,pktcountpb,pktcountw, pktcountpbd,pktcounts)
	except:
	    print "bye!"
            pass
	exit()


###################### Main loop
try:
	print "======================================================="
	print "      ▌ ▌▗   ▛▀▘▗     ▞▀▖       ▞▀▖        ▞▀▖   "
	print "      ▌▖▌▄   ▙▄ ▄     ▌         ▌          ▌     "
	print "      ▙▚▌▐ ▄ ▌  ▐     ▌ ▖overt  ▌ ▖hannel  ▌ ▖hat"
	print "      ▘ ▘▀   ▘  ▀     ▝▀        ▝▀         ▝▀    "
	print "      SECRET & HIDDEN CHAT over WI-FI COVERT CHANNEL"
	print "======================================================="

	# Ask for monitor mode interface
	if len(sys.argv) > 1: 
		if sys.argv[1][:4] == 'wlan':
			if not InitMon(sys.argv[1]): exit(-1)
		elif sys.argv[1][:3] == 'mon':
			intfmon=sys.argv[1]
		else:
			print "First argument must be wlanx or monx!"
			exit(-1)
	else:
	        interface = raw_input("Enter your Wi-Fi interface [%s]: " %defaultinterface)
		if interface == '': interface=defaultinterface
	        if not InitMon(interface): exit(-1)

	# Asks for the alias of the user
	if len(sys.argv) > 2: 
		username=sys.argv[2]
		print "Using nickname: %s" %username
	else:
	        username = raw_input("Enter your User name or alias: ")
		if username == '': exit()
	if username[0] == ":": exit()
	uuid = md5(getmac(intfmon))[7:14]
        userlist[uuid]=username

	# Define private IRC channel
	if len(sys.argv) > 3: 
		privateircname=sys.argv[3]
		print "Using chat room: %s" %privateircname
	else:
	        privateircname = raw_input("Define private IRC channel name: ")
	privateirc=(privateircname * ((16/len(privateircname))+1))[:16]

	# Define private IRC channel password
	if len(sys.argv) > 4: 
		privateirckey=sys.argv[4]
		print "Using encryption key [AES ECB]: %s" %privateirckey
	else:
	        privateirckey = raw_input("Define private IRC robust password: ")
	enckey=(privateirckey * ((16/len(privateirckey))+1))[:16]

	# If history is on, it will keep caching commands to that file
	if history:
		try:
			import readline
			histfile = os.path.join(".chat_history")
			readline.read_history_file(histfile)
			readline.set_history_length(1000)
		except IOError:
			pass

	# Cipher suite: never use ECB in other place than a PoC
	cipher = AES.new(enckey,AES.MODE_ECB) 

	# Calculate channel to be used and mac address - TODO: mac derivation other way
	i=0 ; remote = []
	for i in range(0,6):
		if i < 1:
			remote.append('61')
		else:
			letter = privateirc[i]
			remote.append(letter.encode("hex"))
		if i == 5: channel=max(min(11, ord(letter)/10), 1)
		i += 1
	remote=':'.join(remote).upper()

	# Set channel and begin sniffing in a new thread
	SetChannel(channel)
	sniffer = Thread(target=packetSniffer)
        sniffer.daemon = True
        sniffer.start()

	print "======================================================"
	print "Just write your message and press enter to send!"
	print "or you can use following commands:\n"

	print ":ping:         - ping all the other nodes (test)"
	print ":usrs:         - show all the detected users"
	print ":file:filename - send a file to all the users"
	print ":cmmd:command  - execute local command and send result"
	print ":exit:         - exit (press Ctrl+C if you are a pro!)"
	print "======================================================\n"


except KeyboardInterrupt:
	cleanexit()

try:
	PacketProcessSend("%s joined the chat room: %s" %(username,privateircname)) ## User entering group
	while 1:
	        chat = raw_input()
	        if chat != ":exit:":
			sys.stdout.write("\033[F") # Cursor up one line
			if chat != '':
				PacketProcessSend(chat)
		else:
			cleanexit()
except KeyboardInterrupt:
	cleanexit()
