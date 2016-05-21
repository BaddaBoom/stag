# STAG
It stands for nothing other than "stag" is a word and "steg" is not.

### **About**
This tool is designed to hide text in an image. This is called stegonagraphy and its nothing new.
What is new is that rather than embedding the encoded text at the beginning or ending of an image,
Stag will randomize it somewhere within the image so that adversaries will have a more difficult
time attempting to find the start/end.  In addition, THERE'S ENCRYPTION!

Now, perhaps you find it overkill. I do. Mostly because this is a simple Python (tested on 2.7 and 3.4)
script and theres full blown commercial tools that do this. However, using Pycrypto's AES cipher, the
encryption standards are pretty alright-amazing. Short of getting the key, it \*shouldn't\* be too
east to break. 

So, you get this script, your friend gets this script, you decide out of band what you
want the secret key to be, agree on marker strings (the longer, more unique = the better), and encode
then decode. Simple as that. Enjoy!

### **Usage**
stag.py <encode | decode> <image file> <text file>

The command can either be **encode** - where the **<text file>** is inserted into the **<image file>**,
or **decode** - the **<image file>** is serched for a hidden message, then that message is saved to
**<text file>**.

### **Notes**
#####Dependencies:#####
_PyCrypto_ which can be installed via pip (easy_install I am sure too)
	Linux: "pip install pycrypto"
	Windows: "pip install pycryptodome"
_PIL_ which can be installed via pip (easy_install I am sure too)
	"pip install pillow"
	
#####A word of caution#####
This is just a proof of concept. If you actually do want to use this for covert communication channels
then please be aware of a few things:
	1. theres better reliability in unique markers (less false positives). The other side of the coin,
	though, is that an adversary will have an easier time determining where in the binary lies your
	message. Thats half of the battle.
	2. The other half is the encryption. The message is encrypted with AES and I encourage you to use
	the 256 bit version. To do this make the key a **random** 32 character (read: byte) string. There
	is also support for 128 and 192 but I wont talk about that. I purposely made the key 15 bytes so
	out of the box it wont work. Make it 32 random bytes and we have a plan! Also, I recommend *rotating
	the key each time a new message is generated*. Do this out of band (aka dont send the key in an email
	that you will follow up with the encrypted message, silly.

#####Miscellaneous#####
Sometimes you might get an error about decoding the binary. This is most likely due to a false positive
marker that triggered either an incorrect beginning or an incorrect ending. It is not unusual for this to
happen so I would suggest testing your messages before sending them. If you find that you require very long
markers then experiment around with different versions. As long as the start marker is the first match, and
the end marker is the actual end marker, then you should be fine.

Lastly, this currently only supports PNG output (any RGB-based input can be given). JPEG compression is lossy
(compared to PNG which is lossless). This means that non-human-radible imperfections are removed when the
image is created. This tends to remove parts of our message which is obviously a problem for many reasons.
Future work will be trying to incorporate other lossless image types. GIF or BMP anybody? Anybody? ...