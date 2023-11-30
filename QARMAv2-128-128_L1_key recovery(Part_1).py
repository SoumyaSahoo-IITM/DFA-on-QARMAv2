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


# In[10]:


#faulty ciphertext generation with a random fault at 0th position before round r-1
# let the random fault value be  1001

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

plaintext_u = ["0011", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
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
print("Ciphertext_u3(1001):", "".join(ciphertext_u3))
print("Ciphertext_l3(1001):", "".join(ciphertext_l3))


# In[11]:


#faulty ciphertext generation with a random fault at 0th position before round r-1
# let the random fault value be  1000

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

plaintext_u = ["0010", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
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
print("Ciphertext_u3(1000):", "".join(ciphertext_u3))
print("Ciphertext_l3(1000):", "".join(ciphertext_l3))


#                        0    1    2    3     4    5    6    7     8    9   10   11    12   13   14   15      
# Ciphertext_u3:       1011 0110 1000 1010 /1010 1111 0100 0100 /0110 0011 0000 0101 /0100 1110 1000 1100
# Ciphertext_u3(1001): 1011 0110 1000 1010 /1010 1111 0100 0100 /0110 0011 0000 0101 /0100 1110 1000 1100
# Ciphertext_u3(1000): 1011 0110 1000 1010 /1010 1111 0100 0100 /0110 0011 0000 0101 /0100 1110 1000 1100
# 
#                       16   17   18   19    20   21   22   23    24   25   26   27    28   29   30   31  
# Ciphertext_l3:       1011 0110 0101 0000 /1000 1011 1010 1011 /1001 0001 1100 1100 /0011 0100 1110 0010
# Ciphertext_l3(1001): 1011 0110 0101 0000 /1110 1011 1011 0110 /0110 1100 1100 0101 /0111 1000 0001 0010
# Ciphertext_l3(1000): 1011 0110 0101 0000 /0011 1011 0011 1110 /1111 0101 1100 0001 /0100 1001 0010 0010

# In[16]:


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

d20 = '1110' 
d21 = '1011' 
d22 = '1011' 
d23 = '0110' 
d24 = '0110' 
d25 = '1100' 
d26 = '1100' 
d27 = '0101' 
d28 = '0111' 
d29 = '1000' 
d30 = '0001' 
d31 = '0010'

e20 = '0011' 
e21 = '1011' 
e22 = '0011' 
e23 = '1110'
e24 = '1111' 
e25 = '0101' 
e26 = '1100' 
e27 = '0001' 
e28 = '0100' 
e29 = '1001' 
e30 = '0010'
e31 = '0010'


#########################################################################################################
# unique key recovery of k23,k24 and k29
# Define the Eqn. (4) as in paper:

def equation_valid(c23, c24, c29, d23, d24, d29):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k24 in k_values :
         for k23, k29 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c23, 2) ^ int(k23, 2), '04b')), 2) ^ int(s(format(int(d23, 2) ^ int(k23, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c29, 2) ^ int(k29, 2), '04b')), 2) ^ int(s(format(int(d29, 2) ^ int(k29, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c24, 2) ^ int(k24, 2), '04b')), 2) ^ int(s(format(int(d24, 2) ^ int(k24, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k23 , k24 , k29))
    return valid_keys           

# Check for valid values of keys
valid_keys_set1 = equation_valid(c23, c24, c29, d23, d24, d29)


# Check for valid values of keys
valid_keys_set2 = equation_valid(c23, c24, c29, e23, e24, e29)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("Common Keys: k23,k24,k29")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

#########################################################################################################
# unique key recovery of k20,k27 and k30
# Define the Eqn. (4) as in paper:

def equation_valid(c20, c27, c30, d20, d27, d30):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k30 in k_values :
         for k20, k27 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c20, 2) ^ int(k20, 2), '04b')), 2) ^ int(s(format(int(d20, 2) ^ int(k20, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c30, 2) ^ int(k30, 2), '04b')), 2) ^ int(s(format(int(d30, 2) ^ int(k30, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c27, 2) ^ int(k27, 2), '04b')), 2) ^ int(s(format(int(d27, 2) ^ int(k27, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k20 , k27 , k30))
    return valid_keys           



# Check for valid values of keys
valid_keys_set1 = equation_valid(c20, c27, c30, d20, d27, d30)



# Check for valid values of keys
valid_keys_set2 = equation_valid(c20, c27, c30, e20, e27, e30)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("\n Common Keys: k20,k27,k30")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

#########################################################################################################
# unique key recovery of k22,k25 and k28
# Define the Eqn. (4) as in paper:

def equation_valid(c22, c25, c28, d22, d25, d28):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k25 in k_values :
         for k22, k28 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c22, 2) ^ int(k22, 2), '04b')), 2) ^ int(s(format(int(d22, 2) ^ int(k22, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c25, 2) ^ int(k25, 2), '04b')), 2) ^ int(s(format(int(d25, 2) ^ int(k25, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c28, 2) ^ int(k28, 2), '04b')), 2) ^ int(s(format(int(d28, 2) ^ int(k28, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k22 , k25 , k28))
    return valid_keys           



# Check for valid values of keys
valid_keys_set1 = equation_valid(c22, c25, c28, d22, d25, d28)



# Check for valid values of keys
valid_keys_set2 = equation_valid(c22, c25, c28, e22, e25, e28)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("\n Common Keys: k22,k25,k28")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

