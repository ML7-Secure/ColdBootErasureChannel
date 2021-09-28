import time
import base64
import random
import aes

'''
Program which creates a hexa decayed KS
from a 'clean' KS in bytes
'''
                    
                    ###Utilities###
'''
Tranforms the keys from bytes to hex
'''
def bytes_to_hex(keys=aes.check_ks()): 
    hexKeys = []
    for i in range(0, len(keys)):
        b = keys[i]
        h = base64.b16encode(b).decode()
        hexKeys.append(h)

    return hexKeys

                #       Binary Erasure Channel        #
                        #                    #
                        #       1-p          #
                        # 0 -----------> 0   #
                        #   `   p            # 
                        #      `             #
                        #         `          #
                        #            ` '?'   #
                        #         `          #
                        #      ` p           #
                        #    `               #        
                        #  `    1-p          #
                        # 1 -----------> 1   #
''' Creates a decayed key 
    according to Binary Erasure Channel model'''

def Binary_erasure_channel(p):
    print("\n################################ Binary Erasure Channel ################################\n")
    HexKeys = bytes_to_hex()
    
    keylen = len(HexKeys[0]) # 32

    expanded_decayed_keys_Hex = []
    for j in range(len(HexKeys)): # 11
        decayedHex = []
        for i in range(0, keylen, 2):
            alea = random.randint(1,100) 
            if alea < p:
                decayedHex.append('??') # The whole byte is erased

            else:
                byte = HexKeys[j][i:i+2]
                decayedHex.append(byte)

        decayedRoundHex = ''.join(decayedHex)

        expanded_decayed_keys_Hex.append(decayedRoundHex)

    return expanded_decayed_keys_Hex