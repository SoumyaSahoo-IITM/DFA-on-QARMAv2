#!/usr/bin/env python
# coding: utf-8

# L1 key Recovery of QARMAv2-128-128 for even number of rounds

# In[8]:


#True ciphertext generation

# Define the rotation function
def rho(bits):
    if len(bits) != 4:
        raise ValueError("Input must be a 4-bit binary string")

    # Perform the cyclic left rotation
    rotated_bits = bits[1:] + bits[0]

    return rotated_bits

# Define the Mix column operation
def Mixcolumn(state):
    y = ["0000"] * 16

   
    x0 = state[0]
    x1 = state[1]
    x2 = state[2]
    x3 = state[3]
    x4 = state[4]
    x5 = state[5]
    x6 = state[6]
    x7 = state[7]
    x8 = state[8]
    x9 = state[9]
    x10 = state[10]
    x11 = state[11]
    x12 = state[12]
    x13 = state[13]
    x14 = state[14]
    x15 = state[15]

    y[0] = format(int(rho(x4), 2) ^ int(rho(rho(x8)), 2) ^ int(rho(rho(rho(x12))), 2), '04b')  
    y[1] = format(int(rho(x5), 2) ^ int(rho(rho(x9)), 2) ^ int(rho(rho(rho(x13))), 2), '04b')  
    y[2] = format(int(rho(x6), 2) ^ int(rho(rho(x10)), 2) ^ int(rho(rho(rho(x14))), 2), '04b')  
    y[3] = format(int(rho(x7), 2) ^ int(rho(rho(x11)), 2) ^ int(rho(rho(rho(x15))), 2), '04b')  
        
    y[4] = format(int(rho(x8), 2) ^ int(rho(rho(x12)), 2) ^ int(rho(rho(rho(x0))), 2), '04b')  
    y[5] = format(int(rho(x9), 2) ^ int(rho(rho(x13)), 2) ^ int(rho(rho(rho(x1))), 2), '04b')  
    y[6] = format(int(rho(x10), 2) ^ int(rho(rho(x14)), 2) ^ int(rho(rho(rho(x2))), 2), '04b')  
    y[7] = format(int(rho(x11), 2) ^ int(rho(rho(x15)), 2) ^ int(rho(rho(rho(x3))), 2), '04b') 
        
    y[8] = format(int(rho(x12), 2) ^ int(rho(rho(x0)), 2) ^ int(rho(rho(rho(x4))), 2), '04b')  
    y[9] = format(int(rho(x13), 2) ^ int(rho(rho(x1)), 2) ^ int(rho(rho(rho(x5))), 2), '04b')  
    y[10] = format(int(rho(x14), 2) ^ int(rho(rho(x2)), 2) ^ int(rho(rho(rho(x6))), 2), '04b')  
    y[11] = format(int(rho(x15), 2) ^ int(rho(rho(x3)), 2) ^ int(rho(rho(rho(x7))), 2), '04b')  
        
    y[12] = format(int(rho(x0), 2) ^ int(rho(rho(x4)), 2) ^ int(rho(rho(rho(x8))), 2), '04b')  
    y[13] = format(int(rho(x1), 2) ^ int(rho(rho(x5)), 2) ^ int(rho(rho(rho(x9))), 2), '04b')  
    y[14] = format(int(rho(x2), 2) ^ int(rho(rho(x6)), 2) ^ int(rho(rho(rho(x10))), 2), '04b')  
    y[15] = format(int(rho(x3), 2) ^ int(rho(rho(x7)), 2) ^ int(rho(rho(rho(x11))), 2), '04b')  




    return y


# Define the substitution box (S-box) and shuffle operation (tao)
S_box = [
    "1000", "1010", "1110", "1101",
    "0000", "1001", "0101", "0001",
    "1100", "0010", "1111", "0011",
    "0100", "1011", "0110", "0111"
]

tao = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12]

# Define a random  plaintext array (16 binary 4-bit cells) and  encryption keys
plaintext_u = ["1010", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
             "0000", "0101", "0001", "1101", "1000", "0011", "0010", "1010"]

plaintext_l = ["1011", "1111", "1011", "1001", "1100", "0100", "1010", "1011",
             "0100", "1101", "0101", "1001", "1001", "0001", "0010", "1110"]

key_u = ["0100", "1001", "1110", "0111", "0100", "0000", "1010", "1011",
       "0101", "1101", "1110", "0101", "1010", "1101", "1011", "1001"]

key_l = ["1100", "1000", "1110", "1010", "1001", "0100", "0001", "0011",
       "0101", "0101", "0101", "0011", "1110", "1100", "1010", "0011"]



######################## eXchangeRows

u0 = plaintext_u[0] 
u1 = plaintext_u[1] 
u2 = plaintext_u[2] 
u3 = plaintext_u[3]

l0 = plaintext_l[0] 
l1 = plaintext_l[1] 
l2 = plaintext_l[2] 
l3 = plaintext_l[3]

plaintext_u[0] = l0 
plaintext_u[1] = l1 
plaintext_u[2] = l2 
plaintext_u[3] = l3

plaintext_l[0] = u0 
plaintext_l[1] = u1 
plaintext_l[2] = u2 
plaintext_l[3] = u3


########################## R1...........
##############Upper part############

# Apply the S-box substitution to the plaintext
substituted_plaintext_u1 = [S_box[int(cell, 2)] for cell in plaintext_u]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_u1 = Mixcolumn(substituted_plaintext_u1)


# Apply the shuffle operation using tao
shuffled_plaintext_u1 = [mixed_plaintext_u1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_u1 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_u1)]

#############Lower part##############

# Apply the S-box substitution to the plaintext
substituted_plaintext_l1 = [S_box[int(cell, 2)] for cell in plaintext_l]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_l1 = Mixcolumn(substituted_plaintext_l1)


# Apply the shuffle operation using tao
shuffled_plaintext_l1 = [mixed_plaintext_l1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_l1 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_l1)]

###############################R2........
###################Upper part#################

# Apply the S-box substitution to the plaintext
substituted_plaintext_u2 = [S_box[int(cell, 2)] for cell in ciphertext_u1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_u2 = Mixcolumn(substituted_plaintext_u2)


# Apply the shuffle operation using tao
shuffled_plaintext_u2 = [mixed_plaintext_u2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_u2 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_u2)]

######################Lower part####################

# Apply the S-box substitution to the plaintext
substituted_plaintext_l2 = [S_box[int(cell, 2)] for cell in ciphertext_l1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_l2 = Mixcolumn(substituted_plaintext_l2)


# Apply the shuffle operation using tao
shuffled_plaintext_l2 = [mixed_plaintext_l2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_l2 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_l2)]


########################S.....
###################Upper part###################

# Apply the S-box substitution to the plaintext
substituted_plaintext_u3 = [S_box[int(cell, 2)] for cell in ciphertext_u2]


# XOR the encryption key to get the ciphertext
ciphertext_u3 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(substituted_plaintext_u3)]

#####################Lower part##################

# Apply the S-box substitution to the plaintext
substituted_plaintext_l3 = [S_box[int(cell, 2)] for cell in ciphertext_l2]


# XOR the encryption key to get the ciphertext
ciphertext_l3 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(substituted_plaintext_l3)]


#################### Print the ciphertext
print("Ciphertext_u3:", "".join(ciphertext_u3))
print("Ciphertext_l3:", "".join(ciphertext_l3))


# In[4]:


#faulty ciphertext generation with a random fault at 16th position before round r-1
# let the random fault value be  1110

# Define the rotation function
def rho(bits):
    if len(bits) != 4:
        raise ValueError("Input must be a 4-bit binary string")

    # Perform the cyclic left rotation
    rotated_bits = bits[1:] + bits[0]

    return rotated_bits

# Define the Mix column operation
def Mixcolumn(state):
    y = ["0000"] * 16

   
    x0 = state[0]
    x1 = state[1]
    x2 = state[2]
    x3 = state[3]
    x4 = state[4]
    x5 = state[5]
    x6 = state[6]
    x7 = state[7]
    x8 = state[8]
    x9 = state[9]
    x10 = state[10]
    x11 = state[11]
    x12 = state[12]
    x13 = state[13]
    x14 = state[14]
    x15 = state[15]

    y[0] = format(int(rho(x4), 2) ^ int(rho(rho(x8)), 2) ^ int(rho(rho(rho(x12))), 2), '04b')  
    y[1] = format(int(rho(x5), 2) ^ int(rho(rho(x9)), 2) ^ int(rho(rho(rho(x13))), 2), '04b')  
    y[2] = format(int(rho(x6), 2) ^ int(rho(rho(x10)), 2) ^ int(rho(rho(rho(x14))), 2), '04b')  
    y[3] = format(int(rho(x7), 2) ^ int(rho(rho(x11)), 2) ^ int(rho(rho(rho(x15))), 2), '04b')  
        
    y[4] = format(int(rho(x8), 2) ^ int(rho(rho(x12)), 2) ^ int(rho(rho(rho(x0))), 2), '04b')  
    y[5] = format(int(rho(x9), 2) ^ int(rho(rho(x13)), 2) ^ int(rho(rho(rho(x1))), 2), '04b')  
    y[6] = format(int(rho(x10), 2) ^ int(rho(rho(x14)), 2) ^ int(rho(rho(rho(x2))), 2), '04b')  
    y[7] = format(int(rho(x11), 2) ^ int(rho(rho(x15)), 2) ^ int(rho(rho(rho(x3))), 2), '04b') 
        
    y[8] = format(int(rho(x12), 2) ^ int(rho(rho(x0)), 2) ^ int(rho(rho(rho(x4))), 2), '04b')  
    y[9] = format(int(rho(x13), 2) ^ int(rho(rho(x1)), 2) ^ int(rho(rho(rho(x5))), 2), '04b')  
    y[10] = format(int(rho(x14), 2) ^ int(rho(rho(x2)), 2) ^ int(rho(rho(rho(x6))), 2), '04b')  
    y[11] = format(int(rho(x15), 2) ^ int(rho(rho(x3)), 2) ^ int(rho(rho(rho(x7))), 2), '04b')  
        
    y[12] = format(int(rho(x0), 2) ^ int(rho(rho(x4)), 2) ^ int(rho(rho(rho(x8))), 2), '04b')  
    y[13] = format(int(rho(x1), 2) ^ int(rho(rho(x5)), 2) ^ int(rho(rho(rho(x9))), 2), '04b')  
    y[14] = format(int(rho(x2), 2) ^ int(rho(rho(x6)), 2) ^ int(rho(rho(rho(x10))), 2), '04b')  
    y[15] = format(int(rho(x3), 2) ^ int(rho(rho(x7)), 2) ^ int(rho(rho(rho(x11))), 2), '04b')  




    return y


# Define the substitution box (S-box) and shuffle operation (tao)
S_box = [
    "1000", "1010", "1110", "1101",
    "0000", "1001", "0101", "0001",
    "1100", "0010", "1111", "0011",
    "0100", "1011", "0110", "0111"
]

tao = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12]

# Define the faulty plaintext array (32 binary 4-bit cells) and the encryption keys (32 binary 4-bit cells)

plaintext_u = ["1010", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
             "0000", "0101", "0001", "1101", "1000", "0011", "0010", "1010"]

plaintext_l = ["0101", "1111", "1011", "1001", "1100", "0100", "1010", "1011",
             "0100", "1101", "0101", "1001", "1001", "0001", "0010", "1110"]

key_u = ["0100", "1001", "1110", "0111", "0100", "0000", "1010", "1011",
       "0101", "1101", "1110", "0101", "1010", "1101", "1011", "1001"]

key_l = ["1100", "1000", "1110", "1010", "1001", "0100", "0001", "0011",
       "0101", "0101", "0101", "0011", "1110", "1100", "1010", "0011"]



######################## eXchangeRows

u0 = plaintext_u[0] 
u1 = plaintext_u[1] 
u2 = plaintext_u[2] 
u3 = plaintext_u[3]

l0 = plaintext_l[0] 
l1 = plaintext_l[1] 
l2 = plaintext_l[2] 
l3 = plaintext_l[3]

plaintext_u[0] = l0 
plaintext_u[1] = l1 
plaintext_u[2] = l2 
plaintext_u[3] = l3

plaintext_l[0] = u0 
plaintext_l[1] = u1 
plaintext_l[2] = u2 
plaintext_l[3] = u3


########################## R1...........
##############Upper part############

# Apply the S-box substitution to the plaintext
substituted_plaintext_u1 = [S_box[int(cell, 2)] for cell in plaintext_u]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_u1 = Mixcolumn(substituted_plaintext_u1)


# Apply the shuffle operation using tao
shuffled_plaintext_u1 = [mixed_plaintext_u1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_u1 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_u1)]

#############Lower part##############

# Apply the S-box substitution to the plaintext
substituted_plaintext_l1 = [S_box[int(cell, 2)] for cell in plaintext_l]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_l1 = Mixcolumn(substituted_plaintext_l1)


# Apply the shuffle operation using tao
shuffled_plaintext_l1 = [mixed_plaintext_l1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_l1 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_l1)]

###############################R2........
###################Upper part#################

# Apply the S-box substitution to the plaintext
substituted_plaintext_u2 = [S_box[int(cell, 2)] for cell in ciphertext_u1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_u2 = Mixcolumn(substituted_plaintext_u2)


# Apply the shuffle operation using tao
shuffled_plaintext_u2 = [mixed_plaintext_u2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_u2 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_u2)]

######################Lower part####################

# Apply the S-box substitution to the plaintext
substituted_plaintext_l2 = [S_box[int(cell, 2)] for cell in ciphertext_l1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_l2 = Mixcolumn(substituted_plaintext_l2)


# Apply the shuffle operation using tao
shuffled_plaintext_l2 = [mixed_plaintext_l2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_l2 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_l2)]


########################S.....
###################Upper part###################

# Apply the S-box substitution to the plaintext
substituted_plaintext_u3 = [S_box[int(cell, 2)] for cell in ciphertext_u2]


# XOR the encryption key to get the ciphertext
ciphertext_u3 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(substituted_plaintext_u3)]

#####################Lower part##################

# Apply the S-box substitution to the plaintext
substituted_plaintext_l3 = [S_box[int(cell, 2)] for cell in ciphertext_l2]


# XOR the encryption key to get the ciphertext
ciphertext_l3 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(substituted_plaintext_l3)]


#################### Print the ciphertext
print("Ciphertext_u3(1110):", "".join(ciphertext_u3))
print("Ciphertext_l3(1110):", "".join(ciphertext_l3))


# In[3]:


#faulty ciphertext generation with a random fault at 16th position before round r-1
# let the random fault vaCiphertext_l3(1110): 1011011001010000100010111010101110010001110011000011010011100010lue be  0111

# Define the rotation function
def rho(bits):
    if len(bits) != 4:
        raise ValueError("Input must be a 4-bit binary string")

    # Perform the cyclic left rotation
    rotated_bits = bits[1:] + bits[0]

    return rotated_bits

# Define the Mix column operation
def Mixcolumn(state):
    y = ["0000"] * 16

   
    x0 = state[0]
    x1 = state[1]
    x2 = state[2]
    x3 = state[3]
    x4 = state[4]
    x5 = state[5]
    x6 = state[6]
    x7 = state[7]
    x8 = state[8]
    x9 = state[9]
    x10 = state[10]
    x11 = state[11]
    x12 = state[12]
    x13 = state[13]
    x14 = state[14]
    x15 = state[15]

    y[0] = format(int(rho(x4), 2) ^ int(rho(rho(x8)), 2) ^ int(rho(rho(rho(x12))), 2), '04b')  
    y[1] = format(int(rho(x5), 2) ^ int(rho(rho(x9)), 2) ^ int(rho(rho(rho(x13))), 2), '04b')  
    y[2] = format(int(rho(x6), 2) ^ int(rho(rho(x10)), 2) ^ int(rho(rho(rho(x14))), 2), '04b')  
    y[3] = format(int(rho(x7), 2) ^ int(rho(rho(x11)), 2) ^ int(rho(rho(rho(x15))), 2), '04b')  
        
    y[4] = format(int(rho(x8), 2) ^ int(rho(rho(x12)), 2) ^ int(rho(rho(rho(x0))), 2), '04b')  
    y[5] = format(int(rho(x9), 2) ^ int(rho(rho(x13)), 2) ^ int(rho(rho(rho(x1))), 2), '04b')  
    y[6] = format(int(rho(x10), 2) ^ int(rho(rho(x14)), 2) ^ int(rho(rho(rho(x2))), 2), '04b')  
    y[7] = format(int(rho(x11), 2) ^ int(rho(rho(x15)), 2) ^ int(rho(rho(rho(x3))), 2), '04b') 
        
    y[8] = format(int(rho(x12), 2) ^ int(rho(rho(x0)), 2) ^ int(rho(rho(rho(x4))), 2), '04b')  
    y[9] = format(int(rho(x13), 2) ^ int(rho(rho(x1)), 2) ^ int(rho(rho(rho(x5))), 2), '04b')  
    y[10] = format(int(rho(x14), 2) ^ int(rho(rho(x2)), 2) ^ int(rho(rho(rho(x6))), 2), '04b')  
    y[11] = format(int(rho(x15), 2) ^ int(rho(rho(x3)), 2) ^ int(rho(rho(rho(x7))), 2), '04b')  
        
    y[12] = format(int(rho(x0), 2) ^ int(rho(rho(x4)), 2) ^ int(rho(rho(rho(x8))), 2), '04b')  
    y[13] = format(int(rho(x1), 2) ^ int(rho(rho(x5)), 2) ^ int(rho(rho(rho(x9))), 2), '04b')  
    y[14] = format(int(rho(x2), 2) ^ int(rho(rho(x6)), 2) ^ int(rho(rho(rho(x10))), 2), '04b')  
    y[15] = format(int(rho(x3), 2) ^ int(rho(rho(x7)), 2) ^ int(rho(rho(rho(x11))), 2), '04b')  




    return y


# Define the substitution box (S-box) and shuffle operation (tao)
S_box = [
    "1000", "1010", "1110", "1101",
    "0000", "1001", "0101", "0001",
    "1100", "0010", "1111", "0011",
    "0100", "1011", "0110", "0111"
]

tao = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12]

# Define the faulty plaintext array (32 binary 4-bit cells) and the encryption keys (32 binary 4-bit cells)

plaintext_u = ["1010", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
             "0000", "0101", "0001", "1101", "1000", "0011", "0010", "1010"]

plaintext_l = ["1100", "1111", "1011", "1001", "1100", "0100", "1010", "1011",
             "0100", "1101", "0101", "1001", "1001", "0001", "0010", "1110"]

key_u = ["0100", "1001", "1110", "0111", "0100", "0000", "1010", "1011",
       "0101", "1101", "1110", "0101", "1010", "1101", "1011", "1001"]

key_l = ["1100", "1000", "1110", "1010", "1001", "0100", "0001", "0011",
       "0101", "0101", "0101", "0011", "1110", "1100", "1010", "0011"]



######################## eXchangeRows

u0 = plaintext_u[0] 
u1 = plaintext_u[1] 
u2 = plaintext_u[2] 
u3 = plaintext_u[3]

l0 = plaintext_l[0] 
l1 = plaintext_l[1] 
l2 = plaintext_l[2] 
l3 = plaintext_l[3]

plaintext_u[0] = l0 
plaintext_u[1] = l1 
plaintext_u[2] = l2 
plaintext_u[3] = l3

plaintext_l[0] = u0 
plaintext_l[1] = u1 
plaintext_l[2] = u2 
plaintext_l[3] = u3


########################## R1...........
##############Upper part############

# Apply the S-box substitution to the plaintext
substituted_plaintext_u1 = [S_box[int(cell, 2)] for cell in plaintext_u]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_u1 = Mixcolumn(substituted_plaintext_u1)


# Apply the shuffle operation using tao
shuffled_plaintext_u1 = [mixed_plaintext_u1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_u1 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_u1)]

#############Lower part##############

# Apply the S-box substitution to the plaintext
substituted_plaintext_l1 = [S_box[int(cell, 2)] for cell in plaintext_l]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_l1 = Mixcolumn(substituted_plaintext_l1)


# Apply the shuffle operation using tao
shuffled_plaintext_l1 = [mixed_plaintext_l1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_l1 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_l1)]

###############################R2........
###################Upper part#################

# Apply the S-box substitution to the plaintext
substituted_plaintext_u2 = [S_box[int(cell, 2)] for cell in ciphertext_u1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_u2 = Mixcolumn(substituted_plaintext_u2)


# Apply the shuffle operation using tao
shuffled_plaintext_u2 = [mixed_plaintext_u2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_u2 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_u2)]

######################Lower part####################

# Apply the S-box substitution to the plaintext
substituted_plaintext_l2 = [S_box[int(cell, 2)] for cell in ciphertext_l1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext_l2 = Mixcolumn(substituted_plaintext_l2)


# Apply the shuffle operation using tao
shuffled_plaintext_l2 = [mixed_plaintext_l2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext_l2 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext_l2)]


########################S.....
###################Upper part###################

# Apply the S-box substitution to the plaintext
substituted_plaintext_u3 = [S_box[int(cell, 2)] for cell in ciphertext_u2]


# XOR the encryption key to get the ciphertext
ciphertext_u3 = [format(int(cell, 2) ^ int(key_u[i], 2), '04b') for i, cell in enumerate(substituted_plaintext_u3)]

#####################Lower part##################

# Apply the S-box substitution to the plaintext
substituted_plaintext_l3 = [S_box[int(cell, 2)] for cell in ciphertext_l2]


# XOR the encryption key to get the ciphertext
ciphertext_l3 = [format(int(cell, 2) ^ int(key_l[i], 2), '04b') for i, cell in enumerate(substituted_plaintext_l3)]


#################### Print the ciphertext
print("Ciphertext_u3(0111):", "".join(ciphertext_u3))
print("Ciphertext_l3(0111):", "".join(ciphertext_l3))


#                        0    1    2    3     4    5    6    7     8    9   10   11    12   13   14   15      
# Ciphertext_u3:       1011 0110 1000 1010 /1010 1111 0100 0100 /0110 0011 0000 0101 /0100 1110 1000 1100
# Ciphertext_u3(1110): 1011 0110 1000 1010 /1000 1111 1111 0111 /1010 0010 0000 1111 /0010 1010 1101 1100
# Ciphertext_u3(0111): 1011 0110 1000 1010 /0110 1111 0001 0010 /0101 0110 0000 0111 /0001 1101 1111 1100
# 
#                       16   17   18   19    20   21   22   23    24   25   26   27    28   29   30   31  
# Ciphertext_l3:       1011 0110 0101 0000 /1000 1011 1010 1011 /1001 0001 1100 1100 /0011 0100 1110 0010
# Ciphertext_l3(1110): 1011 0110 0101 0000 /1000 1011 1010 1011 /1001 0001 1100 1100 /0011 0100 1110 0010
# Ciphertext_l3(0111): 1011 0110 0101 0000 /1000 1011 1010 1011 /1001 0001 1100 1100 /0011 0100 1110 0010

# In[5]:


# Unique key recovery of L1 of QARMAv2-128-128

import itertools

#Define the rotation function
def rho(bits):
    if len(bits) != 4:
        raise ValueError("Input must be a 4-bit binary string")

    # Perform the cyclic left rotation
    rotated_bits = bits[1:] + bits[0]

    return rotated_bits

# Define the S-Box
def s(input_bits):
    s_table = {
        '0000': '0100',
        '0001': '0111',
        '0010': '1001',
        '0011': '1011',
        '0100': '1100',
        '0101': '0110',
        '0110': '1110',
        '0111': '1111',
        '1000': '0000',
        '1001': '0101',
        '1010': '0001',
        '1011': '1101',
        '1100': '1000',
        '1101': '0011',
        '1110': '0010',
        '1111': '1010'
    }

    return s_table.get(input_bits, 'Invalid input')

c0 = '1011' 
c1 = '0110' 
c2 = '1000' 
c3 = '1010'
c4 = '1010' 
c5 = '1111' 
c6 = '0100' 
c7 = '0100' 
c8 = '0110' 
c9 = '0011' 
c10= '0000' 
c11= '0101' 
c12= '0100' 
c13= '1110' 
c14= '1000' 
c15= '1100'

c16 = '1011' 
c17 = '0110' 
c18 = '0101' 
c19 = '0000' 
c20 = '1000' 
c21 = '1011' 
c22 = '1010' 
c23 = '1011' 
c24 = '1001' 
c25 = '0001' 
c26 = '1100' 
c27 = '1100'
c28 = '0011' 
c29 = '0100' 
c30 = '1110' 
c31 = '0010'

d4 = '1000'
d5 = '1111' 
d6 = '1111' 
d7 = '0111' 
d8 = '1010' 
d9 = '0010' 
d10 = '0000' 
d11 = '1111' 
d12 = '0010' 
d13 = '1010' 
d14 = '1101' 
d15 = '1100'

e4 = '0110' 
e5 = '1111' 
e6 = '0001' 
e7 = '0010' 
e8 = '0101' 
e9 = '0110' 
e10 = '0000' 
e11 = '0111' 
e12 = '0001' 
e13 = '1101' 
e14 = '1111' 
e15 = '1100'


#########################################################################################################
# unique key recovery of k7,k8 and k13
# Define the Eqn. (6) as in paper:

def equation_valid(c7, c8, c13, d7, d8, d13):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k13 in k_values :
         for k7, k8 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c7, 2) ^ int(k7, 2), '04b')), 2) ^ int(s(format(int(d7, 2) ^ int(k7, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c13, 2) ^ int(k13, 2), '04b')), 2) ^ int(s(format(int(d13, 2) ^ int(k13, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c8, 2) ^ int(k8, 2), '04b')), 2) ^ int(s(format(int(d8, 2) ^ int(k8, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k7 , k8 , k13))
    return valid_keys           

# Check for valid values of keys
valid_keys_set1 = equation_valid(c7, c8, c13, d7, d8, d13)


# Check for valid values of keys
valid_keys_set2 = equation_valid(c7, c8, c13, e7, e8, e13)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("Common Keys: k7,k8,k13")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

#########################################################################################################
# unique key recovery of k4,k11 and k14
# Define the Eqn. (6) as in paper:

def equation_valid(c4, c11, c14, d4, d11, d14):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k14 in k_values :
         for k4, k11 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c4, 2) ^ int(k4, 2), '04b')), 2) ^ int(s(format(int(d4, 2) ^ int(k4, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c14, 2) ^ int(k14, 2), '04b')), 2) ^ int(s(format(int(d14, 2) ^ int(k14, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c11, 2) ^ int(k11, 2), '04b')), 2) ^ int(s(format(int(d11, 2) ^ int(k11, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k4 , k11 , k14))
    return valid_keys           



# Check for valid values of keys
valid_keys_set1 = equation_valid(c4, c11, c14, d4, d11, d14)



# Check for valid values of keys
valid_keys_set2 = equation_valid(c4, c11, c14, e4, e11, e14)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("\n Common Keys: k4,k11,k14")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

#########################################################################################################
# unique key recovery of k6,k9 and k12
# Define the Eqn. (6) as in paper:

def equation_valid(c6, c9, c12, d6, d9, d12):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k9 in k_values :
         for k6, k12 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c6, 2) ^ int(k6, 2), '04b')), 2) ^ int(s(format(int(d6, 2) ^ int(k6, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c9, 2) ^ int(k9, 2), '04b')), 2) ^ int(s(format(int(d9, 2) ^ int(k9, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c12, 2) ^ int(k12, 2), '04b')), 2) ^ int(s(format(int(d12, 2) ^ int(k12, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k6 , k9 , k12))
    return valid_keys           



# Check for valid values of keys
valid_keys_set1 = equation_valid(c6, c9, c12, d6, d9, d12)



# Check for valid values of keys
valid_keys_set2 = equation_valid(c6, c9, c12, e6, e9, e12)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("\n Common Keys: k6,k9,k12")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

