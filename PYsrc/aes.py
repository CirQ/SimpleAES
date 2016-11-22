# #######################################################################
    # -*- encoding: utf-8 -*-
    # File Name: aes.py
    # Author: CirQ
    # mail: CirQ999@163.com
    # Created Time: 2016年10月23日 星期日 13时52分38秒
    # Description: 
# #######################################################################
from Crypto.Cipher import AES

key = "2B7E151628AED2A6ABF7158809CF4F3C".decode("hex")
cipher = AES.new(key, AES.MODE_ECB)
msg = cipher.encrypt("3243F6A8885A308D313198A2E0370734".decode("hex"))
print key.encode("hex")
print msg.encode("hex")
