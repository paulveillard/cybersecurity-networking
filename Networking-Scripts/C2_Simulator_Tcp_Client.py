#!/usr/bin/env python3

'''
Author: AGDC Services
Website: AGDCservices.com
Date: 20210501


This is a Command and Control(C2) Client simulator for TCP traffic

Usage:
    - Fill in the variables at the top of main
    - write your custom C2 code in the "Start of C2 Simulation Code"
      section in main after the client class is instantiated.
      Use the client instance to access the utility
      networking functions. The available functions to the client instance
      are listed at the top of the "Start of C2 Simulation Code" section
    - Run the file from a command prompt using python 3
'''



import ssl
import socket
import sys
import struct
import base64
import time

'''
The following two variables are only needed if TLS is enabled


Details:
    - Create the key and cert on the host where this script will be run
    - fill in the variables below with the key / cert paths
    - set the bDoTls variable in the main function to True

one method to create a TLS key / cert is to use openssl on linux with the following commands
all of the default options can be used when creating the x509 certificate
- openssl genpkey -out <fileName> -algorithm RSA -pkeyopt rsa_keygen_bits:<keyLen in bits>
- openssl req -new -x509 -key <key filePath> -days 7200 -out <fileName>

example:
    openssl genpkey -out key.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048
    openssl req -new -x509 -key key.pem -days 7200 -out cert.cert
'''

gTlsKeyFilePath = r''
gTlsCertFilePath = r''



def main():
    '''
    main function to simulate C2 client network traffic
    '''

    ############################################
    # Initialization Variables
    ############################################

    # initialize variables
    connectingIp = '' # string of dotted decimal ip address to connect to, e.g. '10.10.10.10'
    port = 80 # decimal port number to connect to

    # boolean indicating if TLS should be used
    # fill in the gTlsKeyFilePath and gTlsCertFilePath variables at top of simulator
    # if TLS is enabled
    bDoTls = False

    ############################################



    # error check
    if bDoTls == True and (len(gTlsKeyFilePath) == 0 or len(gTlsCertFilePath) == 0):
        sys.exit('\n[*] ERROR: variables gTlsKeyFilePath and gTlsCertFilePath must be used if TLS is enabled')


    ############################################
    # Start Of C2 Simulation Code
    ############################################

    #
    # Built in Utility Function Prototypes
    # See function headers for usage details
    #
    # Print_Hexdump(byteString)
    #
    # Client(connectingIp, port, bDoTls) # Class Constructor
    # <Client_Class_Instance>.Send(buf)
    # <Client_Class_Instance>.Recv_Len(nLen)
    # <Client_Class_Instance>.Recv_Len_Prepended(lengthOfLengthField, bLittleEndian)
    # <Client_Class_Instance>.Recv_Delim(delim)
    # <Client_Class_Instance>.Socket_Close()
    #


    # initialize the client instance
    client = Client(connectingIp, port, bDoTls)






class Client:
    # Client class which contains all the basic networking
    # utility functions needed to simulate a C2 client

    def __init__(self, host, port, bDoTls):

        print('Starting TCP Client\n')

        # create a socket
        s = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


        # conenct to the tcp server
        s.connect((host, port))


        # if TLS is needed, wrap the socket in the key / cert
        # declared in the global variables at the top of the script
        if bDoTls == True:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.load_cert_chain(keyfile=gTlsKeyFilePath, certfile=gTlsCertFilePath)
            s = context.wrap_socket(s, server_side=False)


        # set instance connection variable to current socket
        # using self.conn variable purely for code reuse in the send / recv
        # functions for both the Client / Server scripts
        self.conn = s



    def Send(self, buf):
        '''
        send entire buffer

        buf must be a byte string
        '''

        # error check
        if isinstance(buf, bytes) == False:
            sys.exit('\n[*] ERROR: buf must be a byte string for Send function')

        self.conn.sendall(buf)


    def Recv_Len(self, nLen):
        '''
        receives a fixed length (nLen) number of bytes
        and returns a byte string of the received bytes
        '''

        result = b''
        bytesRemaining = nLen
        while bytesRemaining > 0:
            result += self.conn.recv(bytesRemaining)
            bytesRemaining = nLen - len(result)


        return result



    def Recv_Len_Prepended(self, lengthOfLengthField, bLittleEndian):
        '''
        receives a packet assuming the packet length preceeds the data
        drops the length part of the bytes and just returns the packet data
        returns a byte string of the received packet data

        lengthOfLengthField should be the number of bytes used to store
        the length of the data portion, e.g. 1,2,4 bytes

        bLittleEndian refers to the endianess of the lengthOfLengthField
        '''

        # determine how to unpack the length field based on function arguments
        endiness = '<' if bLittleEndian == True else '>'
        sizeIndicator = {1:'B', 2:'H', 4:'I'}

        # error check
        if lengthOfLengthField not in sizeIndicator:
            sys.exit('\n[*] error: lengthOfLengthField not valid for this function')


        # build the format string to specify how to unpack the data length
        formatStr = endiness + sizeIndicator[lengthOfLengthField]

        # get the length of the data segment
        dataLen = self.Recv_Len(lengthOfLengthField)

        # transform the length from string to int
        dataLen = struct.unpack(formatStr, dataLen)[0]

        # get the actual data
        data = self.Recv_Len(dataLen)

        return data



    def Recv_Delim(self, delim):
        '''
        receives a packet until you receive the terminating deliminator
        delim must be a byte string
        returns the received bytes, minus the deliminator, as a byte string
        '''

        # error check
        if isinstance(delim, bytes) == False:
            sys.exit('\n[*] ERROR: delim must be a byte string for Recv_Delim function')

        result = b''
        while result.endswith(delim) == False:
            result += self.Recv_Len(1)

        result = result[:-len(delim)]

        return result


    def Socket_Close(self):
        '''
        closes the socket
        '''

        if self.conn is not None:
            self.conn.close()




def Print_Hexdump(data, displayLen = 16):
    '''
    utility function to print the data as a hex dump output
    '''

    # error check
    if isinstance(data, bytes) == False:
        sys.exit('\n[*] ERROR: data must be a byte string for Print_Hexdump function')


    lines = []
    for i in range(0, len(data), displayLen):
        chars = data[i:(i + displayLen)]

        # get standard output views for ????????
        offset = '{:04x}'.format(i)
        hexValues = ' '.join( '{:02x}'.format(i) for i in chars)
        asciiValues = ''.join([chr(i) if i in range(0x20, 0x7f) else '.' for i in chars])

        # add space after every 8 bytes
        charLen = 3 # include space included between hex values
        hexValues = ' '.join( [hexValues[i:(i + charLen*8) ] for i in range(0, len(hexValues) - 0, charLen*8)] )
        charLen = 1 # no space includeed in ascii values
        asciiValues = ' '.join( [asciiValues[i:(i + charLen*8)] for i in range(0, len(asciiValues) - 0, charLen*8) ] )

        # combine all parts of the hexdump into a single list
        spaceAdded = ((3 * displayLen) - 1) / (3 * 8)
        lines.append('{:s}    {:{}s}    {:s}'.format(offset, hexValues, displayLen * 3 + spaceAdded, asciiValues))


    print('\n'.join(lines))
    return '\n'.join(lines)







if __name__ == '__main__':
    main()