#!/usr/bin/python
# -*- coding: utf-8 -*-
from struct import *
import socket,sys,os,random,math,time,commands

class sockClass:

    def __init__(self):
        self.const1 = '\x08\x00'
        self.const2 = 0x0003
        self.const8 = '\x00\x01'
        self.finalLengthIP = 0
        self.headerLengthIP = 5
        self.typeOfServiceIP = 0
        self.vIP = 4
        self.flagIP = 0
        self.offsetIP = 0
        self.socketProtoIP = socket.IPPROTO_TCP
        self.csIP = 0
        self.timeToLiveIP = 255
        self.identifierIP = 45
        self.destinationIP = ''
        self.sourceIP = ''
        self.destinationHost = ''
        self.configCommand = '/sbin/ifconfig'
        self.sourceMACAddr = (commands.getoutput(self.configCommand).split('\n')[0].split()[4])[:]
        self.destinationMACAddr = self.getPhysicalAddr()
        self.minPortNum = 10000
        self.maxPortNum = 20000
        self.sourcePortTCP = random.randint(self.minPortNum, self.maxPortNum)
        self.destinationPortTCP = 80
        self.minSequenceNum = 0
        self.maxSequenceNum = math.pow(2, 31)
        self.sequenceStart = random.randint(self.minSequenceNum, self.maxSequenceNum)
        self.acknowledgementSequenceTCP = 0
        self.finishFlagTCP = 0
        self.resetFlagTCP = 0
        self.pushFlagTCP = 0
        self.synFlagTCP = 0
        self.offsetTCP = 5
        self.acknowledgementFlagTCP = 0
        self.finalTCP = ''
        self.urgentFlagTCP = 0
        self.maxWindowSizeTCP = socket.htons(2008)
        self.csTCP = 0
        self.urgentPointerTCP = 0
        self.congestionWindow = 0x01
        self.receiveQueue = []
        self.receiveWindow = []
        self.bmap = {}
        self.packetTimeoutTCP = 60
        self.timer = time.time()
        self.mTCPVal = ''
        self.acknowledgementClock = 0
        self.seq_timer = 0
        self.duplicateAckTCP = 0
        self.data = ''
        self.orderedArray = []
        self.mSequenceTCP = ''
        self.sequenceClockTCP = 0
        
        try:
            self.sSocket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
            interface = "eth0"
            self.sSocket.bind((interface,0))
        except socket.error, msg:
            print 'Sender could not be created'
            sys.exit()

        try:
            self.rSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
        except socket.error, msg:
            print 'Receiver could not be created'
            sys.exit()

    def csCalc(self, data):
        constant = 0xffff
        shift = 0x01
        checkSumValue = 0
        messageLength = len(data)
        if len(data) % 2 == shift:
            messageLength = 2 * (len(data)/2)

        for index in range(0, messageLength,2):
            tempVal = ord(data[index]) + (ord(data[index + shift]) << 8)
            checkSumValue = tempVal + checkSumValue 
        if len(data) % 2 == shift:
            tempVal = ord(data[-shift])
            checkSumValue = tempVal + checkSumValue

        checkSumValue = (checkSumValue >> 0x10) + (checkSumValue & constant)
        checkSumValue = checkSumValue + (checkSumValue >> 0x10)
        checkSumValue = constant & ~checkSumValue
        return checkSumValue

    def getDLHeader(self):
        return pack("!6s6s2s", self.destinationMACAddr.decode('hex'), self.sourceMACAddr.replace(':','').decode('hex'), self.const1)

    def unpackDLPacket(self, data):
        headerValue= unpack("!6s6s2s",data)
        if headerValue[0]==self.sourceMACAddr.replace(':','').decode('hex') and headerValue[1]==self.destinationMACAddr.decode('hex') and headerValue[0]==self.const1:
            return True
        else:
            return False

    def getTCPHeader(self, payload):
        offset = (self.offsetTCP << 4) + 0
        modifiedFlags = self.finishFlagTCP + (self.synFlagTCP << 0x01) + (self.resetFlagTCP << 2) + (self.pushFlagTCP << 0x0003) + (self.acknowledgementFlagTCP << 4) + (self.urgentFlagTCP << 5)
        headerPackTCP = pack('!HHLLBBHHH',self.sourcePortTCP,self.destinationPortTCP,self.sequenceStart,
                            self.acknowledgementSequenceTCP,offset,modifiedFlags,
                            self.maxWindowSizeTCP,self.csTCP,self.urgentPointerTCP,
                            )
        dataPush = pack('!4s4sBBH',self.sourceAddrIP,self.destinationAddrIP,0,socket.IPPROTO_TCP,len(headerPackTCP) + len(payload))
        dataPush = dataPush + headerPackTCP + payload
        csTCP = self.csCalc(dataPush)
        return pack('!HHLLBBH',self.sourcePortTCP,self.destinationPortTCP,self.sequenceStart,self.acknowledgementSequenceTCP,offset,modifiedFlags,self.maxWindowSizeTCP) + pack('H', csTCP) + pack('!H',self.urgentPointerTCP)

    def packetManipTCP(self,getTCPHeader,headerPackIP,receivedTCPPack):
        receivedTCP = receivedTCPPack
        lengthTCP = len(receivedTCPPack)
        if lengthTCP > 40:
            receivedTCP = receivedTCPPack[40:]
        else:
            receivedTCP = ''
        headerPackTCP = unpack('!HHLLBBHHH', getTCPHeader)
        getTCPHeaderTemp = pack('!HHLLBBHHH',headerPackTCP[0],headerPackTCP[0x01],headerPackTCP[2],headerPackTCP[0x0003],headerPackTCP[4],headerPackTCP[5],headerPackTCP[6],0,headerPackTCP[8])
        headerLengthTCP = len(getTCPHeader)
        recvdTCPLength = len(receivedTCP)
        segmentLength = headerLengthTCP + recvdTCPLength
        dataPush = pack('!4s4sBBH',headerPackIP[0],headerPackIP[0x01],0,socket.IPPROTO_TCP,segmentLength)
        dataPush = dataPush + getTCPHeaderTemp
        dataPush = dataPush + receivedTCP
        csTCP = self.csCalc(dataPush)
        csTCP = unpack('!H', pack('H', csTCP))
        csBool = csTCP[0] == headerPackTCP[7]
        destinationCheck = self.sourcePortTCP == headerPackTCP[0x01]
        sourceCheck = self.destinationPortTCP == headerPackTCP[0]
        if not csBool:
            print 'Checksum is incorrect'

        returnCheck = destinationCheck
        returnCheck = returnCheck & sourceCheck
        returnCheck = returnCheck & csBool
        return returnCheck

    def getHeaderIP(self,payload):
        addedConst = 40
        self.sourceAddrIP = socket.inet_aton(self.sourceIP)
        self.destinationAddrIP = socket.inet_aton(self.destinationIP)
        headerVar = (self.vIP << 4) + self.headerLengthIP
        payloadLength = len(payload)
    	self.finalLengthIP = payloadLength+addedConst
    	self.csIP=0
    	tempHeaderTCP = pack('!BBHHHBBH4s4s',headerVar,
                            self.typeOfServiceIP,self.finalLengthIP,self.identifierIP,
                            self.offsetIP,self.timeToLiveIP,self.csIP,self.socketProtoIP,
                            self.sourceAddrIP,self.destinationAddrIP)
        checkSumValIP = self.csCalc(tempHeaderTCP)
    	self.csIP = unpack('!H',pack('H',checkSumValIP))[0]
    	return pack('!BBHHHBBH4s4s',headerVar,self.typeOfServiceIP,self.finalLengthIP,self.identifierIP,self.offsetIP,self.timeToLiveIP,self.socketProtoIP,self.csIP,self.sourceAddrIP,self.destinationAddrIP)

    def packetManipIP(self, headerIPParam):
        unpackIPHeadParam = unpack('!BBHHHBBH4s4s', headerIPParam)
        return (unpackIPHeadParam[8], unpackIPHeadParam[9])

    def packetSendDataLink(self,payload):
        self.sSocket.send(self.getDLHeader() + payload) 

    def packetResTCP(self):
        self.packetSendDataLink(self.finalTCP)

    def packetSend(self, packet):
        payload = self.getHeaderIP(packet) + self.getTCPHeader(packet) + packet
        self.packetSendDataLink(payload)
        self.sequenceStart = self.sequenceStart + len(packet)
        self.sequenceClockTCP = time.time()
        self.finalTCP = payload

    def messageSendTCP(self):
        self.finishFlagTCP = 0
        self.synFlagTCP = 0
        self.resetFlagTCP = 0
        self.pushFlagTCP = 0x01
        self.acknowledgementFlagTCP = 0x01
        self.urgentFlagTCP = 0
        startIndex = self.sequenceStart - self.mSequenceTCP
        endIndex = startIndex + self.congestionWindow
        subarr = self.mTCPVal[startIndex:endIndex]
        self.packetSend(subarr)

    def reInitializeVar(self, data):
        self.synFlagTCP = 0
        self.resetFlagTCP = 0
        self.finishFlagTCP = 0
        self.acknowledgementFlagTCP = 0x01
        self.urgentFlagTCP = 0
        self.pushFlagTCP = 0x01
        if self.mTCPVal == '':
            self.mSequenceTCP = self.sequenceStart
        self.mTCPVal = data + self.mTCPVal
        self.messageSendTCP()

    def finishTCP(self, data):
        self.synFlagTCP = 0
        self.finishFlagTCP = 0x01
        self.acknowledgementFlagTCP = 0x01
        self.pushFlagTCP = 0
        self.resetFlagTCP = 0
        self.urgentFlagTCP = 0
        emptyS = ''
        self.packetSend(emptyS)

    def acknowledgeTCP(self):
        self.acknowledgementFlagTCP = 0x01
        self.finishFlagTCP = 0
        self.pushFlagTCP = 0
        self.resetFlagTCP = 0
        self.synFlagTCP = 0
        self.urgentFlagTCP = 0
        emptyS = ''
        self.packetSend(emptyS)
        self.acknowledgementClock = time.time()

    def synTCP(self):
        self.urgentFlagTCP = 0
        self.synFlagTCP = 0x01
        self.pushFlagTCP = 0
        self.resetFlagTCP = 0
        self.finishFlagTCP = 0
        self.acknowledgementFlagTCP = 0
        emptyS = ''
        self.packetSend(emptyS)

    def packetReceiveStream(self, size):
        receiveBuffer = self.rSocket.recv(size)
        timer = time.time()
        while True:
            unpackProtocol = unpack('!BBHHHBBH4s4s', receiveBuffer[0:20])[6]
            if socket.IPPROTO_TCP == int(unpackProtocol):
                headerPackIP = self.packetManipIP(receiveBuffer[0:20])
                unpackHeaderTemp = unpack('!4s4s', pack('!4s4s', self.destinationAddrIP,self.sourceAddrIP))
                if unpackHeaderTemp == headerPackIP:
                    valid = self.packetManipTCP(receiveBuffer[20:40], headerPackIP, receiveBuffer)
                    flag = (int(unpack('!HHLLBBHHH', receiveBuffer[20:40])[-4])>> 4) % 2
                    headerPackTCP = unpack('!HHLLBBHHH', receiveBuffer[20:40])
                    if valid:
                        return receiveBuffer
            packetTimeoutTCP = time.time() - self.sequenceClockTCP
            if packetTimeoutTCP > 60:
                self.packetResTCP()
		self.sequenceClockTCP=time.time()
            timeDiff = time.time() - timer
            if timeDiff > 180:
                print 'Time out due to packet not being received within the designated time'
                sys.exit(0)
                break
            receiveBuffer = self.rSocket.recv(size)
        return ''

    def addNewData(self, payload):
        sqNumber = unpack('!HHLLBBHHH', payload[20:40])[2]
        self.bmap[sqNumber] = payload[40:]

    def validQueue(self, payload):
        dataTCP = payload[40:]
        headerPackTCP = unpack('!HHLLBBHHH', payload[20:40])
        self.acknowledgementSequenceTCP = self.acknowledgementSequenceTCP + len(dataTCP)
        orderedArray = sorted(self.bmap.keys())
        if len(orderedArray):
            while self.acknowledgementSequenceTCP == orderedArray[0]:
                sqNumber = orderedArray.pop(0)
                bufferElem = self.bmap[sqNumber]
                dataTCP += bufferElem
                self.acknowledgementSequenceTCP = self.acknowledgementSequenceTCP + len(bufferElem)
                del self.bmap[sqNumber]
                orderedArrayLength = len(orderedArray)
                if orderedArrayLength == 0:
                    break
        return dataTCP

    def recv(self, size):
        packet = self.packetReceiveStream(size)

        while True:
            if len(packet) > 40:
                headerPackIP = self.packetManipIP(packet[0:20])
                headerPackTCP = unpack('!HHLLBBHHH', packet[20:40])
                param = int(headerPackTCP[2])
                if param == self.acknowledgementSequenceTCP:
                    packet = self.validQueue(packet)
                    self.acknowledgeTCP()
                    return packet
                elif param < self.acknowledgementSequenceTCP:
                    self.acknowledgeTCP()
                elif param > self.acknowledgementSequenceTCP:
                    self.addNewData(packet)
            else:
                headerPackTCP = unpack('!HHLLBBHHH', packet[20:40])
                const2 = 0x01
                const3 = 0x10
                headerCheckParam = const2 & headerPackTCP[5]
                headerCheckParam2 = const3 & headerPackTCP[5]
                if headerCheckParam2 == const3:
                    if headerPackTCP[0x0003] == self.sequenceStart:
                        if self.congestionWindow < 1000:
                            self.congestionWindow = self.congestionWindow + const2
                        self.messageSendTCP()
                    else:
                        packetTimeoutTCP = time.time() - self.sequenceClockTCP
                        if packetTimeoutTCP > 60:
                            self.packetResTCP()
                            self.congestionWindow = const2
                        else:
                            self.duplicateAckTCP = self.duplicateAckTCP + const2
                            if self.duplicateAckTCP == 0x0003:
                                self.sequenceStart = headerPackTCP[0x0003]
                                self.congestionWindow = const2
                                self.messageSendTCP()
                if headerCheckParam == const2:
                    self.acknowledgeTCP()
                    return ''
            packet = self.packetReceiveStream(size)
        return packet

    def ackReceiveTCPFinish(self, size):
        payload = self.packetReceiveStream(size)
        const4 = 0x11
        while True:
            if len(payload) == 40:
                headerPackTCP = unpack('!HHLLBBHHH', payload[20:40])
                recvAckCheck = headerPackTCP[5] & const4
                if recvAckCheck == const4:
                    self.acknowledgementSequenceTCP = self.acknowledgementSequenceTCP + 0x01
                    self.acknowledgeTCP()
                    break
            payload = self.packetReceiveStream(size)
        return payload

    def receiveTCPSynPack(self, size):
        const5 = 0x01
        const6 = 0x0003
        payload = self.packetReceiveStream(size)
        while True:
            if len(payload) > 40:
                unpackProtocol = unpack('!BBHHHBBH4s4s', payload[0:20])[6]
                if socket.IPPROTO_TCP == int(unpackProtocol):
                    headerPackIP = self.packetManipIP(payload[0:20])
                    unpackHeaderTemp = unpack('!4s4s', pack('!4s4s',self.destinationAddrIP, self.sourceAddrIP))
                    headerCheckSyn = unpackHeaderTemp == headerPackIP
                    if headerCheckSyn:
                        if self.packetManipTCP(payload[20:40], headerPackIP,payload):
                            headerPackTCP = unpack('!HHLLBBHHH', payload[20:40])
                            paramCheckSyn = int(headerPackTCP[const6])
                            if paramCheckSyn == const5 + self.sequenceStart:
                                self.acknowledgementSequenceTCP = const5 + int(headerPackTCP[2])
                                self.sequenceStart = const5 + self.sequenceStart
                                self.acknowledgeTCP()
                                break

            payload = self.packetReceiveStream(size)

    def getPhysicalAddr(self):
        const7 = 0x0003
        constARP = 0x0806
        constMACHeader = '\xff\xff\xff\xff\xff\xff'
        constARPHeader = '\x00\x00\x00\x00\x00\x00'
        dataLinkSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(const7))
        dataLinkSocket.bind(('eth0', constARP))
        sourceMAC = (commands.getoutput(self.configCommand).split('\n')[0].split()[4])[:]
        sourceIP = (commands.getoutput(self.configCommand).split('\n')[0x01].split()[0x01])[5:]
        ipString = 'route -n'
        endAddrIP = commands.getoutput(ipString).split('\n')[2].split()[0x01]
        destinationMac = ''
        headerValue = pack('!6s6s2s', constMACHeader,sourceMAC.replace(':', '').decode('hex'),'\x08\x06')
        packDLHeader = pack(
            '!2s2s1s1s2s',self.const8,
            self.const1,'\x06',
            '\x04',self.const8,
            )
        resolveSource = pack('!6s4s', sourceMAC.replace(':', '').decode('hex'), socket.inet_aton(sourceIP))
        resolveDest = pack('!6s4s', constARPHeader,socket.inet_aton(endAddrIP))
        finalValue = headerValue + packDLHeader + resolveSource + resolveDest
        dataLinkSocket.send(finalValue)
        while True:
            finalValue = headerValue + packDLHeader + resolveSource + resolveDest
            dataLinkSocket.send(finalValue)
            payload = dataLinkSocket.recv(2048)
            addrResolveArr = payload[14:42]
            if unpack('!6s4s', addrResolveArr[18:28])[0x01] == unpack('!6s4s',resolveSource)[0x01]:
                if unpack('!6s4s', addrResolveArr[8:18])[0x01] == unpack('!6s4s', resolveDest)[0x01]:
                    physicalAddr = unpack('!6s4s',addrResolveArr[8:18])[0x01].encode('hex')
                    return physicalAddr

    def callHandshakeProc(self, hosts):
        self.destinationHost = hosts[0]
        self.destinationIP = socket.gethostbyname(self.destinationHost)
        self.sourceIP = (commands.getoutput(self.configCommand).split('\n')[0x01].split()[0x01])
        self.sourceIP = self.sourceIP[5:]
        self.startTCPHandshake()

    def startTCPHandshake(self):
        maxPort = 0xffff
        maxSequence = math.pow(2, 31)
        randomSeqenceStart = 49152
        receiveSize = 2048
        maxBuffer = 5840
        self.sourcePortTCP = random.randint(randomSeqenceStart, maxPort)
        self.sequenceStart = random.randint(0, maxSequence)
        self.destinationPortTCP = 80
        self.acknowledgementSequenceTCP = 0
        self.offsetTCP = 5 
        self.resetFlagTCP = 0
        self.urgentFlagTCP = 0
        self.pushFlagTCP = 0
        self.acknowledgementFlagTCP = 0
        self.maxWindowSizeTCP = socket.htons(maxBuffer)
        self.csTCP = 0
        self.urgentPointerTCP = 0
        self.synFlagTCP = 0x01
        self.finishFlagTCP = 0
        payload = self.getHeaderIP('') + self.getTCPHeader('')
        self.finalTCP = payload
        self.timer = time.time()
        self.packetSendDataLink(payload)
        self.receiveTCPSynPack(receiveSize)

    def close(self):
        self.finishTCP('')
        self.sequenceStart = 0x01 + self.sequenceStart 
        self.ackReceiveTCPFinish(2048)
        self.sSocket.close()
        self.rSocket.close()