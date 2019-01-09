import sys
import re
import zlib
import getpass
import os
import time

from scapy.all import *

def get_http_headers(http_payload):
    """Get the headers of the http session"""
    try:
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        headers = dict(re.findall(r"(?P<name>.*): (?P<value>.*)\r\n", headers_raw))
    except Exception as e:
        return None
    
    if 'Content-Type' not in headers:
        return None

    return headers

def save_image(headers, http_payload, pictures_directory):
    """Extract and store image from http_payload"""
    
    image_type = headers['Content-Type'].split("/")[1]
    image = http_payload[http_payload.index("\r\n\r\n")+4:]

    if "ETag" in headers.keys():
        filename = headers['ETag']+image_type
    else:
        filename = str(round(time.time()))+image_type

    with open(pictures_directory+filename, "wb") as fp:
        fp.write(image)

def main(argc, argv):
    
    if argc != 2:
        print("Usage: %s filename" % argv[0] )
        sys.exit(1)

    target = re.match(r"[\d.]+", argv[1])
    pictures_directory = "/home/%s/pic_carver/pictures/%s/" % (getpass.getuser(), target.group(0))
    if not os.path.exists(pictures_directory):
        os.makedirs(pictures_directory)
    carved_images = 0

    sessions = rdpcap(argv[1]).sessions()

    for session in sessions:
        http_payload = ""

        for packet in sessions[session]:
            try:
                if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                    http_payload += str(packet[TCP].payload)
            except Exception as e:
                pass
        headers = get_http_headers(http_payload)
        
        if headers is None:
            continue
        save_image(headers, http_payload, pictures_directory)
        carved_images += 1

    print("Carved images: %d" % carved_images)
    sys.exit(0)



if __name__ == '__main__':
    main(len(sys.argv), sys.argv)