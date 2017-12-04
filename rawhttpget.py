#!/usr/bin/python
# -*- coding: utf-8 -*-
import rawPackets,sys
from urlparse import urlparse

def main(args):
    bufferSize = 2048
    receiveSize = 65000
    destinationPort = 80
    defaultName = 'index.html'
    urlSplit = urlparse(args[0])
    pathCheckVar = urlSplit.path
    pathDelim = '/'
    requestType = "GET "
    urlCheck=False
    if args[0][-1]=='/':
        urlCheck=True
    paramURL= args[0].split('/')
    targetHost=paramURL[2]
    if urlCheck:
        paramURL[3:]=''
    requestURL = pathDelim.join(paramURL[3:])
    requestURL = pathDelim + requestURL
    rawsocketObject=rawPackets.sockClass()
    tupleParam = (targetHost,destinationPort)
    rawsocketObject.callHandshakeProc(tupleParam)
    getRequest = requestType+requestURL+" HTTP/1.0\nHost: "
    getRequest = getRequest+targetHost+"\n\n"
    rawsocketObject.reInitializeVar(getRequest)
    serverResponse = rawsocketObject.recv(bufferSize)
    #true=1
    while True:
        responseChunk=rawsocketObject.recv(receiveSize)
        chunkLength = len(responseChunk)
        if chunkLength!=0:
            serverResponse=serverResponse+responseChunk
        else:
            break
            
    rawsocketObject.close()
    initRecvHead = serverResponse.split("\n\n")[0]
    headerModified = initRecvHead.strip("\n\r").split("\r\n")
    responseType = headerModified[0].split(" ")[1]
    responseCode = int(responseType)                                                                                                                                                                              
    if responseCode == 200:
        if pathCheckVar == '':
            localFile = open(defaultName,'w')
        elif len(pathCheckVar) == 1:
            localFile = open(defaultName,'w')
        else:
            fileName = pathCheckVar[1:]
            localFile = open(fileName,'w')
        spaces = '\r\n\r\n'
        replaceData = serverResponse.split("\r\n\r\n")[0]+spaces
        serverResponseModified=serverResponse.replace(replaceData,'')
        data = "".join(serverResponseModified)
        localFile.write(data)#.split("\r\n\r\n")[1:]).strip("\n\r"))
    else :
        error = str(responseCode)
        print("Request failed"+error)
    

if __name__ == "__main__":
  numArgs = len(sys.argv)
  if numArgs != 2:
      print "Specify the URL properly"
  else:
     paramsArray = sys.argv[1:]
     main(paramsArray)
