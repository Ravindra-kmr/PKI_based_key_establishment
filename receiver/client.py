#!/usr/bin/env python3
'''
Author: Ravindra kumar
Function: Implement Client function which either asks or provides a requested file. 
Last Modified: 05-March-2022
Bugs: None
'''

import os
import sys
import socket
import getopt
import base64
import time
from datetime import date
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def start():
	myname, mode, caport,caip, senderip, clientport, outencfile, outfilename,infilename = "","",60000, "", "", 60001,"","",""
    
	try:
	    opts,args = getopt.getopt(sys.argv[1:],"n:m:a:p:q:i:d:s:o:",["name=","caip=","caport=","inputfile=","senderip=","outenc=","outfile="])#,["portnumber=","outputfile="])
	except getopt.GetoptError as err:
	    print(err)
	    print("Syntax: ./client -n myname -m [R|S] [-i inputfile -d senderIP] -q [senderport|clientport] [-s outenc -o outfile] -a caip -p caport")
	    sys.exit(2)
	for o,a in opts:
		if o in ('-n','--name'):
			myname = a
		elif o == '-m':
			mode = a
		elif o in ("-d","--senderip"):
			senderip = a
		elif o in ("-s","--outenc"):
			outencfile = a
		elif o in ("-o","--outfile"):
			outfilename = a
		elif o in ("-i","--inputfile"):
			infilename=a
		elif o == "-q":
			clientport = int(a)
		elif o in ('-a',"--caip"):
			caip = a
		elif o in ("-p","--caport"):
			caport = int(a)
		else:
		    assert False, "unhandled option"
	# print("Input",myname, mode, caport,caip, senderip, clientport, outencfile, outfilename,infilename)

	print("**************************Requesting for Certificate**************************")
	requestCertificate(myname,caport,caip)
	if mode == 'S':
		print("**************************Acting as a Sender**************************")
		Sender(myname,clientport)
	elif mode == 'R':
		print("**************************Acting as a Receiver**************************")
		print("Sleep for 15 seconds.")
		time.sleep(15)
		Receiver(myname,senderip,clientport,infilename,outencfile,outfilename )
	else:
		print("Unknown mode.")
		sys.exit(2)

def requestCertificate(myname,caport,caip):
	certificatefilename = "Certificate.dat"
	cakeyfilename = "capubkey.pem"
	mypubkeyfilename = "clientpubkey.pem"
	myprivkeyfilename = "clientprivkey.pem"
	capubkeyfile = open(cakeyfilename,'rb')
	mypubkeyfile = open(mypubkeyfilename,'rb')
	myprivkeyfile = open(myprivkeyfilename,'rb')
	mypubkey = mypubkeyfile.read()
	RSAcapubkey = serialization.load_pem_public_key(capubkeyfile.read())
	RSAmyprivkey = serialization.load_pem_private_key(myprivkeyfile.read(),password = None)
	mynameb64 = base64.b64encode(myname.encode("ascii"))
	# print(cryptography.__version__)
	encmyname = RSAcapubkey.encrypt(mynameb64,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	dataToCA = "301".encode("ascii")+"|".encode("ascii")+mypubkey+"|".encode("ascii")+base64.b64encode(encmyname)
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
		skt.connect((caip,caport))
		recdata = (skt.recv(2048)).decode()
		print(recdata)
		skt.send(dataToCA)
		print(f"To {(caip,caport)}:Sent 301 request.")
		recdata = skt.recv(2048)
		# print(recdata)
		recdata = recdata.decode("ascii").split('|')
		code = int(recdata[0])
		if code == 302:
			print(f"From {(caip,caport)}:Received 302 information.")
			clientname = base64.b64decode(recdata[1].encode("ascii"))
			certificate = base64.b64decode(recdata[2])
			# print(code,"\nclientname\n",clientname,"\ncertificate\n",certificate)
			enchash = base64.b64decode(recdata[-1])
			signature = RSAmyprivkey.decrypt(enchash,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
			try:
				RSAcapubkey.verify(signature,certificate,padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
			except InvalidSignature as e:
				print("Invalid Signature.")
				sys.exit(3)
			print("Signature matched.")
			certificatefile = open(certificatefilename,"wb")
			certificatefile.write(certificate+'|'.encode("ascii")+base64.b64encode(signature))
			certificatefile.close()
			print(f"Certificate saved in {certificatefilename}.")

def Sender(myname, myport):
	mypubkeyfilename = "clientpubkey.pem"
	myprivkeyfilename = "clientprivkey.pem"
	mypubkeyfile = open(mypubkeyfilename,'rb')
	myprivkeyfile = open(myprivkeyfilename,'rb')
	mypubkey = mypubkeyfile.read()
	RSAmyprivkey = serialization.load_pem_private_key(myprivkeyfile.read(),password = None)
	# print(cryptography.__version__) # 37.0

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
		skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		skt.bind(('',myport)) #open socket to listen on a port number over all interfaces. can use 0.0.0.0 also, same action.
		skt.listen(5)
		conn,addr = skt.accept()
		with conn:
			print(f"Connected to {addr}")
			conn.sendall("Send file request...".encode())
			# while True:
			recdata = conn.recv(2048)
			recdata = recdata.decode("ascii").split('|')
			code = int(recdata[0])
			if code == 501:
				print(f"From {addr}: Received 501 request.")
				recname = base64.b64decode(recdata[1])	#not needed.
				certificatefile = open("Certificate.dat","rb")
				# datatowrite = certificate+base64.b64encode(signature)
				certificate = certificatefile.read()
				certificatefile.close()
				datatosend = "502".encode("ascii") +"|".encode("ascii") + base64.b64encode(myname.encode("ascii"))+"|".encode("ascii") + base64.b64encode(certificate)
				print("Sent certificate to receiver.")
				conn.send(datatosend)

			recdata = conn.recv(2048)
			recdata = recdata.decode("ascii").split('|')
			code = int(recdata[0])
			if code == 503:
				print(f"From {addr}: Received 503 request.")
				encSessionKey =  base64.b64decode(recdata[1])
				requestedFilename = base64.b64decode(recdata[-1]) 
				sessionkey = RSAmyprivkey.decrypt(encSessionKey,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
				print("Decrypted the session key.")
				requestedFile = open(requestedFilename.decode("ascii"),"rb")
				cipher = Cipher(algorithms.AES(sessionkey), modes.CTR(b'0'*16))	# ctr value is all zero. 
				encryptor = cipher.encryptor()
				ct = encryptor.update(requestedFile.read())+encryptor.finalize()
				ct = base64.b64encode(ct)
				datatosend = "504".encode("ascii") +"|".encode("ascii")+ base64.b64encode(requestedFilename)+"|".encode("ascii")+ base64.b64encode(str(len(ct)).encode("ascii"))+ "|".encode("ascii")+ct 
				print(f"To {addr}: Sent the encrypted requested file.\n")
				conn.send(datatosend)

def Receiver(myname, senderip,senderport,infilename,outencfile,outfilename):
	cakeyfilename = "capubkey.pem"
	capubkeyfile = open(cakeyfilename,'rb')
	RSAcapubkey = serialization.load_pem_public_key(capubkeyfile.read())
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
		skt.connect((senderip,senderport))
		recdata = (skt.recv(2048)).decode()
		print(f'From {(senderip,senderport)}: {recdata}')	# Hello message from Sender.
		datatosend = "501".encode("ascii") +"|".encode("ascii") + base64.b64encode(myname.encode("ascii"))
		skt.send(datatosend)
		print(f'To {(senderip,senderport)}: Sent 501 request.')
		recdata = skt.recv(2048)
		# print("Received data: ",recdata)
		recdata = recdata.decode("ascii").split('|')
		code = int(recdata[0])
		if code == 502:
			print(f'From {(senderip,senderport)}: Received 502 information.')
			sendername = base64.b64decode(recdata[1])
			sendercertificatewithhash = base64.b64decode(recdata[2])		#certificate length is 837
			sendercertificatewithhash = sendercertificatewithhash.decode("ascii").split('|')
			sendercertificate =  sendercertificatewithhash[0].encode("ascii")
			signature = base64.b64decode(sendercertificatewithhash[-1])
			try:
				RSAcapubkey.verify(signature,sendercertificate,padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
			except InvalidSignature as e:
				print("Invalid Signature.")
				sys.exit(3)
			print("Signature matched.")
			certExpdate= sendercertificate[-10::1].decode("ascii")
			today = date.today()
			certExpdate = date(int(certExpdate[:4]),int(certExpdate[5:7]),int(certExpdate[8:]))
			if (certExpdate-today).days < 0:
				print("Sender's Certificate expired.")
				sys.exit(3)
			print("Sender's Certificate valid.")
			senderpubkey = ((sendercertificate.decode("ascii")).split("-----"))[1:4]
			senderpubkey = "-----"+"-----".join(senderpubkey)+"-----"
			# print(senderpubkey)
			RSAsenderpubkey = serialization.load_pem_public_key(senderpubkey.encode("ascii"))
			sessionKey = os.urandom(24)
			print("Generated session key.")
			encSessionKey = RSAsenderpubkey.encrypt(sessionKey,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
			print("Encrypted session key with sender's public key.")
			datatosend = "503".encode("ascii") + '|'.encode("ascii") + base64.b64encode(encSessionKey) + '|'.encode("ascii") + base64.b64encode(infilename.encode("ascii"))
			# print(datatosend)
			print(f'Requesting file {infilename}.')
			skt.send(datatosend)
			print(f'To {(senderip,senderport)}: Sent 503 request.')

		recdata = skt.recv(2048)
		recdata = recdata.decode("ascii").split('|')
		code = int(recdata[0])
		if code == 504:
			print(f'From {(senderip,senderport)}: Received 504 information.')
			recinputfilename = base64.b64decode(recdata[1]).decode("ascii")
			if recinputfilename != infilename:
				print("Filename doesnot match. Therefore the sender is not authentic.")
				sys.exit(3)
			filelen = int(base64.b64decode(recdata[2]).decode("ascii"))
			requesteddata = recdata[3].encode("ascii")
			while len(requesteddata) < filelen:
				# print("loop")
				requesteddata += skt.recv(2048)
			requesteddata = base64.b64decode(requesteddata)
			with open(outencfile,"wb") as file:
				file.write(requesteddata)
			print(f'Dumped encrypted data in {outencfile}.')
			cipher = Cipher(algorithms.AES(sessionKey), modes.CTR(b'0'*16))
			decryptor = cipher.decryptor()
			pt = decryptor.update(requesteddata)+decryptor.finalize()
			with open(outfilename,"wb") as file:
				file.write(pt)
			print(f'Dumped requested data in {outfilename}.\n')


if __name__ == "__main__":
	start()