#!/usr/bin/env python3
import sys
import time
import sha_values

def leftrotate(number, n_rotate):
    global mask
    global mode
    return ((number<<n_rotate) | (number >> (int(chunk_len/2)-n_rotate))) & mask


def rightrotate(number, n_rotate):
    global mask
    global chunk_len
    return ((number>>n_rotate) | (number << (int(chunk_len/2)-n_rotate))) & mask

def preprocess(plain_text):
    global word_size
    global chunk_len

    ml = len(plain_text)*8

    # Preprocessing
    # Append bit 1 an retain the multiple of 8 bits
    append_bit = (128).to_bytes(1,'big')
    plain_text = plain_text + append_bit

    # Make the bit length of the final 1024-bit block of the message be 896 bits long
    append_length =  (chunk_len-2*word_size)-(len(plain_text)%chunk_len)
    if append_length < 0:
        append_length = chunk_len - (len(plain_text)%chunk_len) + (chunk_len-2*word_size)
    append_bytes = [(0).to_bytes(1,'big') for bit in range(append_length)]
    append_bytes = b''.join(append_bytes)
    plain_text = plain_text + append_bytes

    ml = ml.to_bytes((word_size*2),'big')
    plain_bytes = plain_text + ml

    return plain_bytes


def get_hash_512(h0,h1,h2,h3,h4,h5,h6,h7):
    hh = '%016x%016x%016x%016x%016x%016x%016x%016x' % (h0, h1, h2, h3, h4, h5, h6, h7)
    return hh

def get_hash_256(h0,h1,h2,h3,h4,h5,h6,h7):
    hh = '%08x%08x%08x%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4, h5, h6, h7)
    return hh

def get_hash_1(h0,h1,h2,h3,h4):
    hh = '%016x%016x%016x%016x%016x%016x%016x%016x' % (h0, h1, h2, h3, h4, h5, h6, h7)
    return hh

def Ch(x,y,z):
    return (x & y) ^ ((~x) & z) 

def Maj(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)

def SUM0(x):
    global mode
    if mode == '512':
        return rightrotate(x,28) ^ rightrotate(x,34) ^ rightrotate(x,39)
    elif mode == '256':
        return rightrotate(x,2) ^ rightrotate(x,13) ^ rightrotate(x,22)

def SUM1(x):
    global mode
    if mode == '512':
        return rightrotate(x,14) ^ rightrotate(x,18) ^ rightrotate(x,41) 
    elif mode == '256':
        return rightrotate(x,6) ^ rightrotate(x,11) ^ rightrotate(x,25)

def o0(x):
    global mode
    if mode == '512':
        return rightrotate(x,1) ^ rightrotate(x,8) ^ (x >> 7)
    elif mode == '256':
        return rightrotate(x,7) ^ rightrotate(x,18) ^ (x >> 3)

def o1(x):
    global mode
    if mode == '512':
        return rightrotate(x,19) ^ rightrotate(x,61) ^ (x >> 6)
    elif mode == '256':
        return rightrotate(x,17) ^ rightrotate(x,19) ^ (x >> 10)

def clear_logs():
    with open('log.txt', 'w') as log:
        log.write('')


def log_state(hs):
    with open('log.txt', 'a+') as log:
        for h in hs:
            log.write(h)
            log.write(' ')
        log.write('\n')

def log_msg(msg):
    with open('log.txt', 'a+') as log:
        log.write(f'{msg}\n')    

if len(sys.argv) < 2:
    print("Format: python SHA.py (filename) (mode)")
    print("modes are: `512`, `256`")
    raise SystemError('Lacking in arguments!')

# Global variables
filename = sys.argv[1]
mode = sys.argv[2]

if mode == '512':
    mask = 0xffffffffffffffff
    chunk_len = 128
    word_size = 8
    crypto_len = 80
    Ks = sha_values.KS512
    hs = sha_values.HS512

elif mode == '256':
    mask = 0xffffffff
    chunk_len = 64
    word_size = 4
    crypto_len = 64
    Ks = sha_values.KS256
    hs = sha_values.HS256

else:
    raise SystemError('Invalid input mode.')


def main():
    global filename
    global mask
    global chunk_len
    global word_size
    global crypto_len
    global hs
    global ks

    # For debugging
    clear_logs()

    # Debuggables
    # log_msg(f'For filename: {filename}')

    with open(filename, 'rb') as f:
        plain_text = f.read()


    plain_bytes = preprocess(plain_text)

    # Debuggables
    # log_msg(f'After Preprocessing: {plain_bytes}')
    

    # Every chunk is a 64-bytes string
    # Which is a 512 bit
    chunks = [plain_bytes[i:i+chunk_len] for i in range(0, len(plain_bytes), chunk_len)]


    # Debuggables
    # log_msg(f'These are the hash values per state during compression')

    for chunk in chunks:
        # Each word is now an integer
        words = [int.from_bytes(chunk[i:i+word_size], byteorder='big') for i in range(0, chunk_len, word_size)]


        a = hs[0]
        b = hs[1]
        c = hs[2]
        d = hs[3]
        e = hs[4]
        f = hs[5]
        g = hs[6]
        h = hs[7]

        # Debugging
        # hs2 = [hex(a),hex(b),hex(c),hex(d),hex(e),hex(f),hex(g),hex(h)]
        # log_state(hs2)

        for i in range(crypto_len):

            if i >= 16:
                word = (o1(words[i-2]) + words[i-7] + o0(words[i-15]) + words[i-16]) & mask
                words.append(word)

                T_1 = (h + SUM1(e) + Ch(e,f,g) + Ks[i] + word) & mask
            else:
                T_1 = (h + SUM1(e) + Ch(e,f,g) + Ks[i] + words[i]) & mask


            T_2 = (SUM0(a) + Maj(a,b,c)) & mask

            h = g
            g = f
            f = e
            e = (d + T_1) & mask
            d = c
            c = b
            b = a
            a = (T_1 + T_2) & mask

            

        hs[0] = (hs[0] + a) & mask
        hs[1] = (hs[1] + b) & mask
        hs[2] = (hs[2] + c) & mask
        hs[3] = (hs[3] + d) & mask
        hs[4] = (hs[4] + e) & mask
        hs[5] = (hs[5] + f) & mask
        hs[6] = (hs[6] + g) & mask
        hs[7] = (hs[7] + h) & mask

    if mode == '512':
        hash_val = get_hash_512(hs[0],hs[1],hs[2],hs[3],hs[4],hs[5],hs[6],hs[7])
    elif mode == '256':
        hash_val = get_hash_256(hs[0],hs[1],hs[2],hs[3],hs[4],hs[5],hs[6],hs[7])        

    print(hash_val)


if __name__ == '__main__':
    start_time = time.time()
    main()
    runtime = time.time() - start_time
    print(f'Runtime lasted for {runtime}s.')
