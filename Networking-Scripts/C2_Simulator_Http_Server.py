#!/usr/bin/env python3

'''
Author: AGDC Services
Website: AGDCservices.com
Date: 20210503


This is a Command and Control (C2) simulator for HTTP traffic
It is a framework that you can fill out to simulate any
C2 server to aid in exercising and analyzing target malware commands

Usage:
    - Fill in the variables at the top of main
    - Fill in desired HTTP response in the do_GET and do_POST functions
    - Run the file from a command prompt
'''



import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import struct
import base64
import cgi


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

gTlsKeyFilePath = ''
gTlsCertFilePath = ''



def main():
    '''
    main function to start http c2 server
    '''

    # initialize variables
    domain = '0.0.0.0' # ip address to listen on
    port = 80 # port number to listen on

    # boolean indicating if HTTPS should be used
    # fill in the gTlsKeyFilePath and gTlsCertFilePath variables at top of simulator
    # if TLS is enabled
    bDoTls = False

    # error check
    if bDoTls == True and (len(gTlsKeyFilePath) == 0 or len(gTlsCertFilePath) == 0):
        sys.exit('\n[*] Error: variables gTlsKeyFilePath and gTlsCertFilePath must be used if TLS is enabled')


    # start http server
    Http_Server(domain, port, Http_Handler, bDoTls)





def Http_Server(host, port, handlerClass, bDoTls):
    '''
    starts a http server to respond to incoming requests
    can handle single or infinite based on line commented out

    '''

    server_class = HTTPServer
    httpd = server_class( (host, port), handlerClass)

    if bDoTls == True:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(keyfile=gTlsKeyFilePath, certfile=gTlsCertFilePath)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)


    print('Starting Http Server\n')
    try:
        httpd.serve_forever()
        #httpd.handle_request()
    except KeyboardInterrupt:
        pass



class Http_Handler(BaseHTTPRequestHandler):
    '''
    handler class which holds code to build GET / POST response
    '''

    # initialize static class variables
    nGetCount = 0
    nPostCount = 0


    def log_message(self, format, *args):
        '''
        included so python doesn't print out log messages
        '''
        pass

    def _Set_Headers(self, bufSend = None):
        self.send_header('Content-type', 'text/html')
        self.send_header('Fake_C2_Http_Header', 'text/html')
        if bufSend != None:
            self.send_header('Content-Length', bufSend.__len__())
        self.end_headers()


    def do_GET(self):
        '''
        respond to GET requests
        '''

        # get url requested in GET requests
        host = self.headers['host']
        path = self.path

        self.__class__.nGetCount += 1
        print('\nreceived GET request #{:02d} to {:s}{:s}'.format(self.__class__.nGetCount, host, path))


        # initialize response data to send
        bufSend = b'D' * 16



        # send reponse to GET requests
        self.send_response(200) # required for real HTTP functions to parse request
        if bufSend != None:
            self._Set_Headers()
            self.wfile.write(bufSend)


    def do_POST(self):
        '''
        respond to POST requests
        '''

        # get POST request parameters of interest
        host = self.headers['host']
        path = self.path
        #dataLen = int(self.headers.getheader('Content-Length'))
        dataLen = int(self.headers['Content-Length'])
        ctype, pdict = cgi.parse_header(self.headers['Content-Type'])
        if ctype == 'multipart/form-data':
            pdict['boundary'] = bytes(pdict['boundary'], 'utf-8')
            fieldsDict = cgi.parse_multipart(self.rfile, pdict)
        else:
            bufRecv = self.rfile.read(dataLen)


        self.__class__.nPostCount += 1
        print('\nreceived POST request #{:02d} to {:s}{:s}'.format(self.__class__.nPostCount, host, path))


        # initialize response data to send
        bufSend = b'D' * 16



        # send response to POST request
        self.send_response(200) # required for real HTTP functions to parse request
        if bufSend != None:
            self._Set_Headers(bufSend)
            self.wfile.write(bufSend)


def Print_Hexdump(data, displayLen = 16):
    '''
    utility function to print the data as a hex dump output
    '''

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