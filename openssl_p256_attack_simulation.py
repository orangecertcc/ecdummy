#!/usr/bin/env python3

import sys
import os


'''
generate a message for signing given the name of the file
'''
def gen_message(msg_filename, n):
    message = 'Lorem ipsum dolor sit amet' + str(n)
    open(msg_filename, 'w').write(message)


'''
generate a signature given a private key and a message
openssl_bin_path should be the complete path of the openssl binary
that has been altered to produce a fault in last addition of scalar multiplication
with the specific implementation of curve P-256
'''
def gen_signature(openssl_bin_path, privkey_filename, msg_filename, sig_filename):
    command = openssl_bin_path + ' dgst -sha256 -sign ' + privkey_filename + ' -out ' + sig_filename + ' ' + msg_filename
    os.system(command)
    

'''
Simulation of the attack
Signatures and messages are stored in the directory list_sig_directory
'''
def launch_attack(openssl_bin_path, privkey_filename, list_sig_directory, nsig, verb=False):
    if not os.path.exists(list_sig_directory):
        os.mkdir(list_sig_directory)
    if len(os.listdir(list_sig_directory)) != 0:
        os.system('rm ' + list_sig_directory + '/*')
    
    if verb:
        print('Signatures and messages will be stored in the directory ' + list_sig_directory)
        print('Generating {} signatures with fault in last point addition...'.format(nsig))
   
    for n in range(nsig):
        msg_filename = list_sig_directory + '/message_{}.txt'.format(n)
        sig_filename = list_sig_directory + '/signature_{}.bin'.format(n)
        gen_message(msg_filename, n)
        gen_signature(openssl_bin_path, privkey_filename, msg_filename, sig_filename)
    if verb:
        print('  ... done')


def printhelp():
    print('Arguments are:')
    print('   #1: /path/to/altered/openssl')
    print('   #2: /path/to/privatekey')
    print('   #3: /path/to/directory_of_signatures_and_messages')
    print('   #4: number of signatures to attack (default: 2500)')


if __name__ == '__main__':
    argc = len(sys.argv) - 1
    if argc != 3 and argc != 4:
        printhelp()
        sys.exit()

    if argc == 3:
        nsig = 2500
    else:
        nsig = int(sys.argv[4])
        
    launch_attack(sys.argv[1], sys.argv[2], sys.argv[3], nsig, verb=True) 
    
