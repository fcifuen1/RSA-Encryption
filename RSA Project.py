# CMSC 443 Cryptology - RSA Algorithm Project
#
# Federico Cifuentes-Urtubey (fcifuen1)
# Created: November 1st, 2016
#
# This program's limitation is that it only works with decrypting
# lowercase strings without spaces

import random
from time import time

# Alg. 5.3 - Euclid's alg. to find the multiplicative inverse of a (mod b)
def MultInverse(b,a):
    a0 = a
    b0 = b
    t0 = 0
    t = 1
    q = int(a0 / b0)
    r = a0 - (q * b0)

    while r > 0:
        temp = (t0 - (q * t)) % a
        t0 = t
        t = temp
        a0 = b0
        b0 = r
        q = int(a0 / b0)
        r = a0 - (q * b0)
    
    if b0 == 1:
        return t
        
    return str(b) + " has no multiplicative inverse mod " + str(a)


# Alg. 5.5 - Returns x^c mod n
def SquareMult(x,c,n):
    z = 1
    l = c.bit_length()

    # bin(c) will return '0b' in the front of the string
    binary = bin(c)[2:]

    for i in range(l):
        z = (z * z) % n

        if binary[i] == '1':
            z = (z * x) % n

    return z


# Alg. 5.2 - Extended Euclidean Algorithm 
def gcd(a,b):    
    a0 = a
    b0 = b
    t0 = 0
    t = 1
    s0 = 1
    s = 0
    q = int(a0 / b0)
    r = a0 - (q * b0)

    while r > 0:
        temp = t0 - (q * t)
        t0 = t
        t = temp
        temp = s0 - (q * s)
        s0 = s
        s = temp
        a0 = b0
        b0 = r
        q = int(a0 / b0)
        r = a0 - (q * b0)

    r = b0

    return r


# Returns True if n is (probably) a prime number, False if n is composite
def MillerRabinTest(n):
    if n == 2:
        return True
    if n < 2 or n % 2 == 0:
        return False

    # n - 1 = 2^(k) * m
    k = 0
    m = n - 1

    while m % 2 == 0:
        m /= 2
        k += 1

    a = random.randrange(1, n)
    b = SquareMult(a, m, n)
    
    if b == (n + 1) % n:
        return True

    for i in range(k):
        if b == (n - 1) % n:
            return True
        else:
            b = SquareMult(b, 2, n)
            
    return False

# Returns a randomly generated prime 512 bits long
def genPrime():
    flag = False

    while not flag:
        n = random.getrandbits(512)

        if n % 2 == 0:
            n += 1

        primePasses = 0

        for p in range(10):
            if MillerRabinTest(n):
                primePasses += 1

        if primePasses == 10:
            flag = True
                
    return n


# Returns two tuples that form the public key and private key 
def genKeyPair(p,q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Make a random int r such that r and phi are relatively prime
    b = random.randrange(2, phi - 1)

    #print("Finding gcd(b,phi)...")
    g = gcd(b, phi)
    
    while g != 1:
        b = random.randrange(1, phi)
        g = gcd(b, phi)

    a = MultInverse(b, phi)

    fid = open('cifuentes-urtubey_key.txt', 'w')
    fid.write(str(n) + '\n' + str(b))    
    fid.close()

    fid = open('cifuentes-urtubey_privkey.txt', 'w')
    fid.write("n = " + str(n) + '\n')
    fid.write("a = " + str(a) + '\n')
    fid.write("b = " + str(b) + '\n')
    fid.write("p = " + str(p) + '\n')
    fid.write("q = " + str(q) + '\n')
    fid.close()
    
    # (pubKey, privKey)
    return (n,b), (n,a)


# Returns an encrypted plaintext, y = x^b mod n
# pubKey = (n,b)
def Encrypt(pubKey, text):
    ciphertext = 0

    # [letter in Z26] * 26^(i) for each char (in order left to right),
    # where i = length of the text - 1
    for c in range(len(text)):
        ciphertext += (ord(text[c]) - 97) * (26 ** (len(text) - c - 1))

    ciphertext = SquareMult(ciphertext, pubKey[1], pubKey[0])  

    return ciphertext


# Returns a decrypted ciphertext, x = y^a mod n
# privKey = (n,a)
def Decrypt(privKey, text):
    plaintext = ""
    text = SquareMult(text, privKey[1], privKey[0])
    
    k = 0
    while text > 0:
        l = ( text % (26 ** (k + 1)) ) / (26 ** k)
        text -= l * (26 ** k)                # remove char from encryption
        plaintext = chr(l + 97) + plaintext  # adds chars backwards
        k += 1
    
    return plaintext
    

def main():
    ti = time()

    message = "iwantanewwaterbottle"

    t1 = time()
    p = genPrime()
    t2 = time()

    # Generating p ranges from 0.51 to 6+ seconds on my machine
    print("Generated p in: " + str(t2 - t1) + " seconds")
    
    t1 = time()
    q = genPrime()
    t2 = time()

    # Generating q ranges from 0.44 to 8+ seconds on my machine
    print("Generated q in: " + str(t2 - t1) + " seconds" + '\n')

    #print("P = " + str(p) + '\n')
    #print("Q = " + str(q) + '\n')
    
    pubKey, privKey = genKeyPair(p,q)

    #y = Encrypt(pubKey, message)
    #print("Y = " + str(y))
    #print("X = " + Decrypt(privKey, y) + '\n')

    
    # n_main and a_main is the private key for the pub key I sent in the email
    n_main = 74550924417846863652667066871367445685641461364428319995457292353260615021789047942276632416008426147746716636141963562375383555320033152254402870094583437878282504681113623226736063473585706170809563172605704756772272631106175413359381780372875201302665307086988262999803762851261516025160020301817346582289

    a_main = 40110030610611193948250667346865485830898432522544602169840666209388503610090192157100369011878574787477119677546860716625409059900644009673678188020341678594452148819095557799115761390956662264259054395167887907833910999835897659657191999375117724159786183470064002705105912494402388375272876472269575915283
    
    fid = open('cifuentes-urtubey_cipher.txt', 'r')
    num = long(fid.readline())
    fid.close()

    fid = open('cifuentes-urtubey_xstr.txt', 'w')
    fid.write( Decrypt((n_main, a_main),num) )
    fid.close()
    print("Wrote decryption into file cifuentes-urtubey_xstr.txt")

    tf = time()

    # Fastest time: 0.578 seconds
    #print("Program execution time: " + str(tf - ti) + " seconds")
    
main()
