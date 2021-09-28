import time
import base64
import random
import aes
import aeskeyschedule as KS
from keyDecaying import Binary_erasure_channel, bytes_to_hex
import math
import matplotlib.pyplot as plt


# Round constant words
RCON = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# S-box and Inverse S-box (S is for Substitution)
S = [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
# = [   01,   02, ...      

#Useful for the Brute-force part
def hamming_distance(chaine1, chaine2):
    return sum(c1 != c2 for c1, c2 in zip(chaine1, chaine2))

def correcting_errors(hexDecayedKeys):
    
    # transform keys into 4x4 matrices
    matricesKeys = []
    for i in range(11):
        roundKey = hexDecayedKeys[i]
        tk = [roundKey[i:i + 8] for i in range(0, 32, 8)]
        matricesKeys.append(tk)
        print(tk)

    go_on = True # if it's blocked everywhere nothing can be done otherwise we go on
    while go_on:
        go_on = False

        # Check if there is a subkey without any error
        ctr = []
        for i in range(len(matricesKeys)):
            target_key = ''.join(matricesKeys[i])
            c = 0
            for j in range(32):
                if target_key[j:j+2] == '??': 
                    c+=1
            
            ctr.append(c)

        if 0 in ctr: # If a subkey is without error we stop
            goal = ctr.index(0) # we get the index of the no error key
            target_key = ''.join(matricesKeys[goal]) # we get the no error key
            print('\nfound sub-key without error :', target_key)
            tkey = int(target_key, 16)
    
            base_key = tkey.to_bytes(16, byteorder='big')
            first_key = KS.reverse_key_schedule(base_key, goal) # We perform the KS from this no error key
            
            finalKS = KS.key_schedule(first_key)
            final_KS = bytes_to_hex(finalKS)

            print('\ncorrected key schedule :')
            print(final_KS)
            
            print('\nMaster key :', final_KS[0], '\n')
            return True


        for target in range(len(matricesKeys)):
            for i in range(4):
                for k in range(0,8,2):

                    # Try to calculate the bytes of the first columns (using S-Box, RCON) of the *previous* key (especially useful for the 1st column of 1st key)
                    res = ''; byte1 = ''; byte2 = ''
                    if target < 10 and i == 0 and matricesKeys[target][0][k:k+2] == '??' and k < 6 and matricesKeys[target+1][0][k:k+2] != '??' and matricesKeys[target][3][k+2:k+4] != '??': # For the 1st column of 1st key
                        go_on = True

                        b1 = matricesKeys[target+1][0][k:k+2]
                        b2 = matricesKeys[target][3][k+2:k+4]

                        byte1 = hex(S[int(b2, 16)]).lstrip('0x') # Subs operation

                        if len(byte1) != 2:
                            byte1 = '0'+byte1

                        byte2 = b1

                        if k == 0: # 1st byte depends on the RCON
                            res = hex( int(byte1,16) ^ RCON[target] ^ int(byte2,16) ).lstrip('0x').upper()

                        else: 
                            res = hex( int(byte1,16) ^ int(byte2,16) ).lstrip('0x').upper()
                        
                        if len(res) != 2:
                            res = '0'+res
                        
                        tmp = list(matricesKeys[target][0])
                        
                        tmp[k] = res[0].upper(); tmp[k+1] = res[1].upper()
                        matricesKeys[target][0] = ''.join(tmp)

                    # The last byte depends on the first one because of the RotWord operation
                    elif target < 10 and i == 0 and matricesKeys[target][0][6:8] == '??' and k == 6 and matricesKeys[target+1][0][6:8] != '??' and matricesKeys[target][3][0:2] != '??':
                        go_on = True

                        b1 = matricesKeys[target+1][0][6:8]; b2 = matricesKeys[target][3][0:2]
                        
                        byte1 = hex(S[int(b2, 16)]).lstrip('0x')
                       
                        if len(byte1) != 2:
                            byte1 = '0'+byte1

                        byte2 = b1

                        res = hex(int(byte1,16) ^ int(byte2,16)).lstrip('0x').upper() # this one doesn't use RCON

                        if len(res) != 2:
                            res = '0'+res
                        
                        tmp = list(matricesKeys[target][0])

                        tmp[k] = res[0].upper(); tmp[k+1] = res[1].upper()
                        matricesKeys[target][0] = ''.join(tmp)


                    # Try to calculate the bytes of the first columns (using S-Box, RCON) of the *following* key (the other way)
                    res = ''; byte1 = ''; byte2 = ''
                    if target < 10 and matricesKeys[target+1][0][k:k+2] == '??' and k < 6 and matricesKeys[target][0][k:k+2] != '??' and matricesKeys[target][3][k+2:k+4] != '??':
                        go_on = True

                        b1 = matricesKeys[target][0][k:k+2]; b2 = matricesKeys[target][3][k+2:k+4]
                        
                        byte1 = hex(S[int(b2, 16)]).lstrip('0x')
                        
                        if len(byte1) != 2:
                            byte1 = '0'+byte1

                        byte2 = b1

                        if k == 0: # 1st byte depends on the RCON
                            res = hex( int(byte1,16) ^ RCON[target] ^ int(byte2,16) ).lstrip('0x').upper()
                        
                        else: 
                            res = hex( int(byte1,16) ^ int(byte2,16) ).lstrip('0x').upper()
                        
                        if len(res) != 2:
                            res = '0'+res
                        
                        tmp = list(matricesKeys[target+1][0])
                        
                        tmp[k] = res[0].upper(); tmp[k+1] = res[1].upper()
                        matricesKeys[target+1][0] = ''.join(tmp)

                    # The last byte depends on the first one because of the RotWord operation
                    elif target < 10 and matricesKeys[target+1][0][6:8] == '??' and k == 6 and matricesKeys[target][0][6:8] != '??' and matricesKeys[target][3][0:2] != '??':
                        go_on = True

                        b1 = matricesKeys[target][0][6:8]; b2 = matricesKeys[target][3][0:2]
                        
                        byte1 = hex(S[int(b2, 16)]).lstrip('0x')
                        if len(byte1) != 2:
                            byte1 = '0'+byte1
                       
                        byte2 = b1

                        res = hex(int(byte1,16) ^ int(byte2,16)).lstrip('0x').upper() # this one doesn't use RCON

                        if len(res) != 2:
                            res = '0'+res

                        tmp = list(matricesKeys[target+1][0])
                        
                        tmp[k] = res[0].upper(); tmp[k+1] = res[1].upper()
                        matricesKeys[target+1][0] = ''.join(tmp)


                    # no RCON or S-Box (simple XOR)
                    res = ''; byte1 = ''; byte2 = ''
                    if matricesKeys[target][i][k:k+2] == '??':
                        if target == 0 and i == 0:
                            continue # Do not attack the 1st column of the first key here
                            
                        if target == 0 : # if we attack the 1st key (not the 1st column), we have to use the following subkey

                            byte1 = matricesKeys[target+1][i-1][k:k+2]
                            byte2 = matricesKeys[target+1][i][k:k+2]
                            
                            if byte1 == '??' or byte2 == '??':
                                continue
                        
                        elif target != 0 and i == 0 and '??' in matricesKeys[target][0]: # One of the way to attack the 1st column (not for the 1st key here)
                            byte1 = matricesKeys[target][i+1][k:k+2]
                            byte2 = matricesKeys[target-1][i+1][k:k+2]

                            if byte1 == '??' or byte2 == '??':
                                continue
                        
                        else: # all the bytes not in the 1st columns (using the previous subkey)
                        
                            byte1 = matricesKeys[target][i-1][k:k+2]
                            byte2 = matricesKeys[target-1][i][k:k+2]

                            if byte1 == '??' or byte2 == '??':
                                continue
                        
                        res = hex(int(byte1,16) ^ int(byte2,16)).lstrip('0x')
                        go_on = True
                        if len(res) != 2: # == 1
                            res = '0'+res

                        tmp = list(matricesKeys[target][i])

                        tmp[k] = res[0].upper(); tmp[k+1] = res[1].upper()
                        matricesKeys[target][i] = ''.join(tmp)

        # Calculations "in the other way" (beginning at the last subkey), for the simple XOR operation
        for target in reversed(range(len(matricesKeys))):
            for i in range(4):
                for k in range(0,8,2):
                    if target == 0 and i == 0: # Do not exploit the 1st column of 1st key this time
                        break

                    res = ''; byte1 = ''; byte2 = ''
                    if matricesKeys[target][i][k:k+2] == '??':
                        
                        if target == 10 and i != 0: # if we attack the last key, we have to use the previous subkey
                            byte1 = matricesKeys[target][i-1][k:k+2]
                            byte2 = matricesKeys[target-1][i][k:k+2]

                            if byte1 == '??' or byte2 == '??':
                                continue
                        
                        elif target != 0 and i == 0 and '??' in matricesKeys[target][0]: # if we attack the 1st column (not for the 1st key)
                            byte1 = matricesKeys[target][i+1][k:k+2]
                            byte2 = matricesKeys[target-1][i+1][k:k+2]

                            if byte1 == '??' or byte2 == '??':
                                continue
                        
                        else: # all the bytes not in the 1st columns (using the following subkey)
                            byte1 = matricesKeys[target+1][i-1][k:k+2]
                            byte2 = matricesKeys[target+1][i][k:k+2]

                            if byte1 == '??' or byte2 == '??':
                                continue
                        
                        res = hex(int(byte1,16) ^ int(byte2,16)).lstrip('0x')
                        go_on = True
                        if len(res) != 2:
                            res = '0'+res
                        
                        tmp = list(matricesKeys[target][i])
                        
                        tmp[k] = res[0].upper()
                        tmp[k+1] = res[1].upper()
                        
                        matricesKeys[target][i] = ''.join(tmp)
        
        print('Research stage :')
        for i in range(len(matricesKeys)):
            print(matricesKeys[i])

        if 1 in ctr and not go_on:# If it's blocked and a subkey has only 1 erased byte, we brute-force it
            goal = ctr.index(1) # we get the index of the sub-key
            target_key = ''.join(matricesKeys[goal]) # we get the sub-key
            erasedIndex = target_key.index('?')
            print('\nfound sub-key with 1 erased byte :', target_key)
            time.sleep(0.2)

            distances = []; keySchedules = []
            for res in range(0x0, 0xff + 1):
                res = format(res, 'X')
                if len(res) == 1:
                    res = '0'+res
                
                tmp = list(target_key)
                tmp[erasedIndex] = res[0]
                tmp[erasedIndex+1] = res[1]

                target_key = ''.join(tmp)
                print('trying :', target_key)

                #KS then HD between the createed KS and the decayed KS
                tkey = int(target_key, 16)
        
                base_key = tkey.to_bytes(16, byteorder='big')
                first_key = KS.reverse_key_schedule(base_key, goal) # We perform the KS from this no error key
                
                finalKS = KS.key_schedule(first_key)
                final_KS = bytes_to_hex(finalKS)

                hd = 0; temp = 0
                for i in range(len(matricesKeys)): #we perform the KS
                    hd += hamming_distance(''.join(matricesKeys[i]), final_KS[i]) # and the HD

                distances.append(hd)
                #keySchedules.append(final_KS) # Use lot of RAM but useful if the right byte is '00' (very rare) #**#

                if len(distances) > 1:
                    if abs(distances[-1] - distances[-2]) > 50:
                        #ind_hd = distances.index(min(distances)) #**#
                        print('\ncorrected key schedule :')
                        #print(keySchedules[ind_hd]) #**#
                        print(final_KS)

                        #print('\nMaster key :', keySchedules[ind_hd][0], '\n') #**#
                        print('\nMaster key :', final_KS[0], '\n')
                        return True

        #if 2 in ctr and not go_on: # ?interesting?

    print('\nKS impossible to rebuild')
    return False

def cold_boot(p):
    expanded_decayed_keys = Binary_erasure_channel(p)
    return correcting_errors(expanded_decayed_keys)

def plotResults():
    maxErasureRate = 30
    liste = [math.ceil(100*(1 - pow(1-(i/100), 8))) for i in range(1, maxErasureRate)] # Erasure rate (on bytes)
    results = []

    for p in liste:
        print('p =', p)
        passed = 0
        for i in range(10):
            res = cold_boot(p)
            print('trial', i+1)
            if res:
                passed +=1

        results.append(passed)
    
    plt.title('Number of passed reconstructions on 10 trials')
    plt.xlabel('Erasure Percentage')
    plt.ylabel('Passed Reconstruction')

    plt.scatter(liste, results)
    plt.plot(liste, results)
    plt.show()

def main(): 
    p = int(input("Erasure Percentage : "))
    cold_boot(p)

if __name__ == '__main__':
    main() 
    #plotResults()
    
