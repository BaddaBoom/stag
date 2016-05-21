#!/usr/bin/env python

'''
A simple Steganography tool that implements AES Encryption

This tool will ingest a text file of a message, encrypt it, then write the
message into the image supplied. The tool can then be used to read
the text inside of the file, the tool can decrypt the message into a 
human-readable form.

Copyright 2013 @BaddaBoom

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Please see the LICENSE file for more information.

'''

import sys
import binascii
import base64
import os
import random
from Crypto.Cipher import AES
from PIL import Image

'''
Globals
    If you want to retrieve the message properly, you will need these as they were during encoding
'''
G_Start_Str = '01010101010101010101010101010101' # moved to 4 bytes.
G_Stop_Str = '101010101010101010101010101010101' # moved to 4 bytes
G_Secret_Key = b"BEST_CHANGE_ME!!" # make this 16 bytes

'''
Encryption Class
    Handles the AES encrypting/decrypting routines for the hidden messages
'''
class Encryption:
    # constructor
    def __init__(self, blocksize=16, padding=b"#"):
        self.secret = G_Secret_Key
        self.pad_char = padding
        self.blk_size = blocksize
        self.iv = os.urandom(self.blk_size)

    # pad the message to be the block size if necessary
    def pad(self, msg):
        return msg + (self.blk_size - len(msg) % self.blk_size) * self.pad_char

    # encrypt and encode message
    def encrypt(self, msg):
        try:
            self.cipher = AES.new(self.secret, AES.MODE_CBC, self.iv)
        except Exception as e:
            print("[!] ERROR: " + str(e))
            return None
        return base64.b64encode(self.iv + self.cipher.encrypt(self.pad(msg))) 
    
    # decode and decrypt the message
    def decrypt(self, emsg):
        try:
            decoded = base64.b64decode(emsg)
            self.iv = decoded[:self.blk_size]
            self.cipher = AES.new(self.secret, AES.MODE_CBC, self.iv)
        except Exception as e:
            print("[!] ERROR: " + str(e))
            return None
        return self.cipher.decrypt(decoded[self.blk_size:]).rstrip(self.pad_char)

'''
Stag Class
    The steganography class object for hiding and finding text in an image
'''
class Stag:   
    # constructor
    def __init__(self):
        self.startstr = G_Start_Str
        self.stopstr = G_Stop_Str
        self.marker = "" # this will level at len of startstr and have a FIFO buffer to check

    # hides the text into the image
    def hide(self, img, filename, msg):
        binary = self.startstr + bin(int(binascii.hexlify(msg), 16)) + self.stopstr
        if img.mode in "RGBA":
            img = img.convert("RGBA")
            data = img.getdata()
            new_data = []
            digit = 0
            binlen = len(binary)
            datalen = len(data)
            pxcount = 0
            # we need to make sure the binary message isnt larger than the image or we lose data
            if datalen > binlen:
                rstop = datalen - binlen
                startat = random.randrange(0, rstop, 2)
                for d in data:
                    if (digit < len(binary)) and (pxcount >= startat):
                        hexcode = '#{:02x}{:02x}{:02x}'.format(d[0], d[1], d[2])[:-1] + binary[digit] # replace the lower byte with the next character in our binary string
                        r = int(hexcode[1:3], 16) # skip the # sign
                        g = int(hexcode[3:5], 16)
                        b = int(hexcode[5:7], 16)
                        new_data.append((r,g,b,255)) # append the new/encoded pixel
                        digit += 1
                    else:
                        new_data.append(d) # apend the original pixel
                    pxcount += 1
                img.putdata(new_data)
                # JPEG compresion does not work in our favor
                # TODO: find a way to keep the entire hidden message together in JPEG
                img.save(filename + "-stag.png", "PNG")
                return True
            else:
                print("[!] ERROR: message is too big for image!")
        return False
        
    # used to locate the start of our message
    def found_msg_start(self, pos):
        if self.marker == self.startstr:
            return True # check for match first
        if len(self.marker) < len(self.startstr):
            self.marker += pos
            return False # marker isnt full
        # update marker FIFO
        self.marker = self.marker[1:] + pos
        return False

    # retrieve the message from the image
    def show(self, img):
        binary = ''
        if img.mode in "RGBA":
            img = img.convert("RGBA")
            data = img.getdata()          
            for d in data:
                digit = '#{:02x}{:02x}{:02x}'.format(d[0], d[1], d[2])[-1]
                if self.found_msg_start(digit):
                    if digit in "01": # if is binary
                        binary += digit # add the digit to our binary string
                        if binary[-len(self.stopstr):] == self.stopstr:
                            try:
                                strstr = binascii.unhexlify('%x' % (int('0b' + binary[:-len(self.stopstr)], 2))) # return the converted binary string
                            except binascii.Error:
                                print("[!] ERROR: could not determine the full hidden message. This is usually caused by false markers. Make the markers longer and/or more unique.")
                            except Exception as e:
                                print("[!] ERROR: " + str(e))
                            else:
                                return strstr
        return None

'''
Usage
    display how to use the tool
'''
def usage():
    print("USAGE: " + sys.argv[0] + " <command> <image.file> <text.file>\n")
    print("\tCOMMANDS:")
    print("\t\tencode\t\tWill hide the <text.file> inside the <image.file>")
    print("\t\tdecode\t\tWill retrieve the message text from <image.file> and write it to <text.file>\n")
    print("\tFILES:")
    print("\t\timage.file\tA picture to hide the hidden text within.)")
    print("\t\ttext.file\tIs either a file containing the message to hide or will be the output for the hidden text.\n\n")
    sys.exit(1)

'''
Main Entry Point
    Handles arg parsing and setup
'''
if __name__ == '__main__':
    print("\n\n .----------------.  .----------------.  .----------------.  .----------------. ")
    print("| .--------------. || .--------------. || .--------------. || .--------------. |")
    print("| |    _______   | || |  _________   | || |      __      | || |    ______    | |")
    print("| |   /  ___  |  | || | |  _   _  |  | || |     /  \\     | || |  .' ___  |   | |")
    print("| |  |  (__ \\_|  | || | |_/ | | \\_|  | || |    / /\\ \\    | || | / .'   \\_|   | |")
    print("| |   '.___`-.   | || |     | |      | || |   / ____ \\   | || | | |    ____  | |")
    print("| |  |`\\____) |  | || |    _| |_     | || | _/ /    \\ \\_ | || | \\ `.___]  _| | |")
    print("| |  |_______.'  | || |   |_____|    | || ||____|  |____|| || |  `._____.'   | |")
    print("| |              | || |              | || |              | || |              | |")
    print("| '--------------' || '--------------' || '--------------' || '--------------' |")
    print(" '----------------'  '----------------'  '----------------'  '----------------' ")
    print("                                      A steganography tool to hide your secrets.\n")

    # are the args right
    if len(sys.argv) != 4:
        usage()

    # what are we trying to do with the image
    if sys.argv[1].upper() == "ENCODE":
        cmd = 1
    elif sys.argv[1].upper() == "DECODE":
        cmd = 2
    else:
        print("[!] Invalid command!")
        usage()

    # ENCODING ROUTINE
    if cmd == 1:
        try:
            img = Image.open(sys.argv[2])
        except IOError:
            print("[!] Not a valid image file!")
            sys.exit(1)

        try:
            with open(sys.argv[3], "rb") as f:
                message = f.read()
        except IOError:
            print("[!] Could not open file: " + str(sys.argv[3]))
            sys.exit(1)

        # encrypt the data now
        encr = Encryption()
        emsg = encr.encrypt(message)

        if emsg is not None:
            # hide the encrypted data
            steg = Stag()
            if steg.hide(img, os.path.splitext(sys.argv[2])[0], emsg):
                print("[+] Message was hidden successfully!")
            else:
                print("[!] Error while hiding message!")
        else:
            print("[!] Could not encrypt message")
         
            
    # DECODING ROUTINE
    elif cmd == 2:
        try:
            img = Image.open(sys.argv[2])
        except IOError:
            print("[!] Not a valid image file!")
            sys.exit(1)
            
        # show the data
        steg = Stag()
        emsg = steg.show(img)

        # decrypt the data
        if emsg is not None:
            decr = Encryption()
            message = decr.decrypt(emsg)
            if message is not None:
                with open(sys.argv[3], "wb") as f:
                    f.write(message)
                print("[+] Text output to " + sys.argv[3])
            else:
                print("[!] Could not decrypt message")
    
        else:
            print("[!] Error: No hidden text was found")
        
    # "MEH..." ROUTINE
    else:
        print("[!] Unknown command!")
        sys.exit(1)

    print("\n")
    sys.exit(0)
