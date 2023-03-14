import hashlib, os, binascii

#-----------------------------------------------------------------------------------------------
#   starting values
#   q - prime number, order of cyclic group G
#   g - generator of group G (its primitive root) / also usually a public value
#   p - used for modular multiplication, also a prime number such that p = 2q + 1

q = 146213
g = 2 
p = 292427 #p is such that 2q - 1 = p where p is prime

#-----------------------------------------------------------------------------------------------
#   utilities for managing the types

def bytes_to_number(s):
    #convert bytes string to number
    return int(binascii.hexlify(s), 16)

def number_bytes_to_str(val1, val2):
    #convert numbers and bytes strings to string
    string_val = str(val1)+str(val2)
    return string_val.encode()

#-----------------------------------------------------------------------------------------------
#   other functions, mostly generating values

def generate_ephemeral_key():
    #generate a fresh ephemeral secret key
    rand_val = os.urandom(12) 
    esk = hashlib.sha512(rand_val).digest()
    return esk


def H1(esk, sk):
    #hash function H1(esk, sk)
    #H1 --> H1: {0,1}^* --> ℤ𝑞
    h_input = number_bytes_to_str(esk,sk)       #the number_bytes_to_str takes care of encoding
    h1 = hashlib.sha512(h_input).digest()
    return bytes_to_number(h1) % q              #return the numerical value of calculated hash


def check_session_keys(session_kA, session_kB):
    #compare session keys computed on side A and B
    if session_kA == session_kB:
        print("\nboth computed session keys are the same!")
    else:
        print("\nthe session keys are not the same..")

def initiating_party_session_key_input(esk, sk, pk, id_A, id_B):
    #compute and concatenate session key input of the initiating party (we assume A)
    #K = H2(val_k1, val_k2, val_k3, val_k4, val_k5)
    #K = H2(Y^skA, pkB^H1(eskA, skA), Y^H1(eskA, skA), ID_A, ID_B)
    hash_mod = H1(esk, sk) % p
    val_k1 = pow(Y,sk,p)
    val_k2 = pow(pk, hash_mod,p)
    val_k3 = pow(Y, hash_mod,p)
    key_input = str(val_k1) + str(val_k2) + str(val_k3) + id_A + id_B
    return key_input

def recieving_party_session_key_input(esk, sk, pk, id_A, id_B):
    #compute and concatenate session key input of the recieving party (we assume B)
    #K = H2(val_k1, val_k2, val_k3, val_k4, val_k5)
    #K = H2(pkA^H1(eskB,skB), X^skB, X^H1(eskB,skB), ID_A, ID_B)
    hash_mod = H1(esk, sk) % p
    val_k1 = pow(pk,hash_mod,p)
    val_k2 = pow(X, sk, p)
    val_k3 = pow(X,hash_mod,p)
    key_input = str(val_k1) + str(val_k2) + str(val_k3) + id_A + id_B
    return key_input

def H2(sskey_input):
    #hash function H2, used for session key
    h2 = hashlib.new('sha512')
    h2.update(sskey_input.encode())
    session_key = h2.digest()
    return session_key


#-----------------------------------------------------------------------------------------------

#   NAXOS PROTOCOL 
#              
#   skA, skB - long term secret key
#   pkA, pkB - long public key (pk = g^sk)
#   eskA, eskB - ephemeral secret key (random but the same length as the output of H2 function)
#   X, Y - computed value sent over the unsecure channel X = g^H1(eskA,skA), Y = g^H1(eskB,skB)
#   id_A, id_B - identity of a party (string value)

#-----------------------------------------------------------------------------------------------

id_A = "Alice"
id_B = "Bob"

skA = 20437654686587653 % q                       
print("this is skA: ", skA)

pkA = pow(g,skA,p)                   #calculate public key pkA:
print("this is pkA: ", pkA)

skB = 66918976967567567 % q
print("this is skB: ", skB)      

pkB = pow(g,skB,p)                   #calculate public key pkB:
print("this is pkB: ", pkB)


#   EPHEMERAL KEY(s)
#   to generate an ephemeral key we choose a crypto random value and hash it with the same hashing funciton as H2

eskA = generate_ephemeral_key()
print("this is ephemeral key A: ", eskA)

eskB = generate_ephemeral_key()
print("this is ephemeral key B: ", eskB)

#   g^H1(eskA, skA) ---> its an exponent of X (which A sends to B)

x_exponent = H1(eskA, skA)
#print("this is H1(eskA, skA): ", x_exponent)

#   g^H1(eskB, skB) ---> its an exponent of Y (which B sends to A)

y_exponent = H1(eskB, skB)
#print("this is H1(eskB, skB): ", y_exponent)


#----------------   calculate X (for side A)

X = pow(g,x_exponent,p)             #X = g^H1(eskA,skA)
print("this is value X: ",X)

#-----------------  calculate Y (for side B)

Y = pow(g,y_exponent,p)             #Y = g^H1(eskB,skB)
print("this is value Y: ", Y)


#   calculate SESSION KEY(s) on both sides

#   A -> KA = H2(Y^skA, pkB^H1(eskA, skA), Y^H1(eskA, skA), ID_A, ID_B)

sessionKA_input = initiating_party_session_key_input(eskA, skA, pkB, id_A, id_B)
session_keyA = H2(sessionKA_input)

print("\nthis is session key on the side A:\n", session_keyA)

#   B -> KB = H2(pkA^H1(eskB,skB), X^skB, X^H1(eskB,skB), ID_A, ID_B)

sessionKB_input = recieving_party_session_key_input(eskB, skB, pkA, id_A, id_B)
session_keyB = H2(sessionKB_input)

print("\nthis is session key on the side B:\n", session_keyB)

#   checking if the session key is the same on both sides

check_session_keys(session_keyA, session_keyB)