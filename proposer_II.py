from flask import Flask, request
from flask_restful import Resource, Api, reqparse, abort
import json
import requests
import random
import hashlib
import zmq
import sys
from threading import Thread
import time
import random
import string
import sys
import ecdsa
import hashlib
import binascii
import os



class Proposer:
    API_URL = 'http://127.0.0.1:5000/peers'
    HOST = '127.0.0.1'
    SERVER_PORT = '5000/chord'

    def __init__(self, portNo, n, k, m, txNo, r):
        self.n = int(n)  # no. of peers
        self.k = int(k)  # threshold for tolerable malicious peers
        self.m = int(m)  # no. of malicious peers
        self.txNo = int(txNo)  # no. transactions per block
        self.r = int(r)  # no. of rounds (blocks)
        self.h = ""  # set to empty string as it is the first block
        self.h2 = ''
        self.honestPeers = self.n - self.m #  total no. of peers - no. of malicious peers
        self.firstGroup = self.honestPeers // 2
        self.secondGroup = self.honestPeers - self.firstGroup

        self.myPORT = int(portNo)
        if os.path.exists('chain_%d.txt' % self.myPORT):
            os.remove('chain_%d.txt' % self.myPORT)
        else:
            print("The file does not exist")

        self.sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p, hashfunc = hashlib.sha256)  # SECRET KEY
        self.pk = self.sk.get_verifying_key()  # PUBLIC KEY - BYTE FORMAT
        pkSTR = binascii.hexlify(self.pk.to_string()).decode('utf-8')  # PUBLIC KEY - STR FORMAT

        endpoint = '{}'.format(self.API_URL)
        requests.put((endpoint), json={'PORT': self.myPORT, 'PUBKEY': pkSTR}) # if buggy, check this

    def generateBlock(self):
        # generate a block of l transactions
        # each transaction is a random string
        # the first block of transactions
        print("generating block...")
        self.block = self.h
        for i in range(0, self.txNo):
            tx = "".join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
            self.block += tx + "\n"
        self.h = hashlib.sha256(self.block.encode('utf-8')).hexdigest()

        print("The transaction block: \n", self.block)
        self.signature = self.sk.sign(self.block.encode('utf-8'))

        print("Signature for the block: ", binascii.hexlify(self.signature))

    def generateBlock2(self):
        # generate a block of l transactions
        # each transaction is a random string
        # the first block of transactions
        print("generating block...")
        self.block2 = self.h2
        for i in range(0, self.txNo):
            tx = "".join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
            self.block2 += tx + "\n"
        self.h2 = hashlib.sha256(self.block2.encode('utf-8')).hexdigest()

        print("The transaction block: \n", self.block2)
        self.signature2 = self.sk.sign(self.block2.encode('utf-8'))

        print("Signature for the block: ", binascii.hexlify(self.signature2))

    def contactValidators(self):

        endpoint = '{}'.format(self.API_URL)
        response = requests.get((endpoint))  # if buggy, check this
        content = response.json()
        listOfPeers = content['Peers']

        validatorsPortList = []
        for i in listOfPeers: # excluding self.PORT from list of ports
            if i['PORT'] != self.myPORT:
                validatorsPortList.append(i['PORT'])

        for numberOfRound in range(self.r):
            self.generateBlock()
            self.generateBlock2()
            message = {'BLOCK': self.block,
                       'SIGNATURE': self.signature.hex(), # change bytes to string
                       'PORT': self.myPORT}  # message to be sent :)

            message2 = {'BLOCK': self.block2,
                       'SIGNATURE': self.signature2.hex(),  # change bytes to string
                       'PORT': self.myPORT}  # message to be sent :)

            #  message to be sent to malicious peers
            maliciousMessage = {'BLOCK': self.block,
                                'SIGNATURE': self.signature.hex(), # change bytes to string
                                'PORT': self.myPORT,
                                'BLOCK2': self.block2,
                                'SIGNATURE2': self.signature2.hex()}  # message to be sent :)

            receivedMsgs = 0  # counter
            numMessagesSent = 0
            signatureList = []
            self.sentToValidators = False
            while(receivedMsgs < 2*self.k):

                if not self.sentToValidators:
                    self.sentToValidators = True

                    for peer in validatorsPortList: # send REQ(msg) to all validators
                        context = zmq.Context()
                        php = 'tcp://127.0.0.1:' + str(peer) # how and where to connect
                        proposerSocket = context.socket(zmq.REQ)  # create socket
                        proposerSocket.connect(php)  # block until connected

                        if (self.myPORT + self.m > peer):
                        # if(numMessagesSent < self.m-1): # if we still didn't send to all malicious peers
                            proposerSocket.send_json(maliciousMessage)  # send message
                            print('Sending to validator: ', peer, 'Message: ', maliciousMessage)
                        elif (self.myPORT + self.m <= peer and peer < self.myPORT + self.m + self.firstGroup):
                        # elif ( self.m -1 <= numMessagesSent and numMessagesSent < self.firstGroup+self.m -1):
                            proposerSocket.send_json(message)  # send message
                            print('Sending to validator: ', peer, 'Message: ', message)
                        elif (peer >= self.myPORT + self.m + self.firstGroup):
                        #elif (self.firstGroup+self.m -1 <= numMessagesSent):
                            proposerSocket.send_json(message2)  # send message
                            print('Sending to validator: ', peer, 'Message: ', message2)

                        numMessagesSent = numMessagesSent + 1

                        malPeer = False
                        response = proposerSocket.recv_json()  # receive validation

                        print("proposer received message: ", response)

                        for i in listOfPeers:  # finding the public key of the sender thru its port num.
                            if i['PORT'] == response['PORT']:
                                peerPubK = i['PUBKEY']

                        peerSignature = response['SIGNATURE']
                        peerSignature = bytes.fromhex(peerSignature)
                        block = response['BLOCK']
                        if 'BLOCK2' in response:
                            peerSignature2 = response['SIGNATURE2']
                            peerSignature2 = bytes.fromhex(peerSignature2)
                            block2 = response['BLOCK2']
                            malPeer = True #added new ******

                        encodedPK = peerPubK.encode('utf-8')  # convert string PK to Bytes
                        ecdsaPK = ecdsa.VerifyingKey.from_string(binascii.unhexlify(encodedPK), curve=ecdsa.NIST256p,
                                                                 hashfunc=hashlib.sha256)  # convert to ecdsa object
                        signatureList.append(response['SIGNATURE'])
                        try:  # verifying the receieved block
                            print(ecdsaPK.verify(peerSignature, block.encode('utf-8')))
                            if(malPeer):
                                print(ecdsaPK.verify(peerSignature2, block2.encode('utf-8')))
                            print('Block verified in proposer!')
                            receivedMsgs = receivedMsgs + 1
                            print('Number of received messages from validators: ', receivedMsgs)
                        except ecdsa.BadSignatureError:
                            print(ecdsa.BadSignatureError)
                            print('Block not verified in proposer!')

            #  ***********should the two messages be appended?**************
            self.f = open('chain_%d_II.txt' % self.myPORT, 'a+')  # CREATE FILE
            self.f.write(message['BLOCK'])
            self.f.write('Signatures: ')
            self.f.write('\n')
            for sign in signatureList:
                self.f.write(str(sign))
                self.f.write('\n')
            self.f.close()
        return


