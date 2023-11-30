#!/usr/bin/env python
# coding: utf-8

# L1 key Recovery of QARMAv2-64

# In[1]:


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
plaintext = ["1010", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
             "0000", "0101", "0001", "1101", "1000", "0011", "0010", "1010"]

key1 = ["1100", "1101", "1110", "1111", "0000", "0001", "0010", "0011",
       "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011"]

key0 = ["1000", "1100", "1010", "1110", "0001", "0000", "0011", "1011",
       "0101", "0111", "0111", "0011", "1010", "1101", "0010", "0011"]

# R1...........

# Apply the S-box substitution to the plaintext
substituted_plaintext1 = [S_box[int(cell, 2)] for cell in plaintext]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext1 = Mixcolumn(substituted_plaintext1)


# Apply the shuffle operation using tao
shuffled_plaintext1 = [mixed_plaintext1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext1 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext1)]


#R2........

# Apply the S-box substitution to the plaintext
substituted_plaintext2 = [S_box[int(cell, 2)] for cell in ciphertext1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext2 = Mixcolumn(substituted_plaintext2)


# Apply the shuffle operation using tao
shuffled_plaintext2 = [mixed_plaintext2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext2 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext2)]


#S.....

# Apply the S-box substitution to the plaintext
substituted_plaintext3 = [S_box[int(cell, 2)] for cell in ciphertext2]


# XOR the encryption key to get the ciphertext
ciphertext3 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(substituted_plaintext3)]



# Print the ciphertext
print("Ciphertext3:", "".join(ciphertext3))


# In[3]:


#faulty ciphertext generation with a random fault at 1st position before round r-1
# let the random fault value be  0101

# Define the rotation function
def rho(bits):
    if len(bits) != 4:
        raise ValueError("Input must be a 4-bit binary string")

    # Perform the cyclic left rotation
    rotated_bits = bits[1:] + bits[0]

    return rotated_bits

# Define the Mixcolumn operation
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

# Define the faulty plaintext array (16 binary 4-bit cells) and the encryption keys

plaintext = ["1010", "0010", "1001", "1011", "1100", "0110", "1110", "1111",
             "0000", "0101", "0001", "1101", "1000", "0011", "0010", "1010"]

key1 = ["1100", "1101", "1110", "1111", "0000", "0001", "0010", "0011",
       "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011"]

key0 = ["1000", "1100", "1010", "1110", "0001", "0000", "0011", "1011",
       "0101", "0111", "0111", "0011", "1010", "1101", "0010", "0011"]

# R1...........

# Apply the S-box substitution to the plaintext
substituted_plaintext1 = [S_box[int(cell, 2)] for cell in plaintext]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext1 = Mixcolumn(substituted_plaintext1)


# Apply the shuffle operation using tao
shuffled_plaintext1 = [mixed_plaintext1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext1 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext1)]


#R2........

# Apply the S-box substitution to the plaintext
substituted_plaintext2 = [S_box[int(cell, 2)] for cell in ciphertext1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext2 = Mixcolumn(substituted_plaintext2)


# Apply the shuffle operation using tao
shuffled_plaintext2 = [mixed_plaintext2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext2 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext2)]

#S.....

# Apply the S-box substitution to the plaintext
substituted_plaintext3 = [S_box[int(cell, 2)] for cell in ciphertext2]



# XOR the encryption key to get the ciphertext
ciphertext3 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(substituted_plaintext3)]



# Print the ciphertext
print("Ciphertext3:", "".join(ciphertext3))


# In[4]:


#faulty ciphertext generation with a random fault at 1th position before round r-1
#Let the fault value be 1100

#Define the rotation function
def rho(bits):
    if len(bits) != 4:
        raise ValueError("Input must be a 4-bit binary string")

    # Perform the cyclic left rotation
    rotated_bits = bits[1:] + bits[0]

    return rotated_bits

# Define the Mixcolumn operarion
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

# Define the faulty plaintext array (16 binary 4-bit cells) and the encryption keys

    
plaintext = ["1010", "1011", "1001", "1011", "1100", "0110", "1110", "1111",
             "0000", "0101", "0001", "1101", "1000", "0011", "0010", "1010"]

key1 = ["1100", "1101", "1110", "1111", "0000", "0001", "0010", "0011",
       "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011"]

key0 = ["1000", "1100", "1010", "1110", "0001", "0000", "0011", "1011",
       "0101", "0111", "0111", "0011", "1010", "1101", "0010", "0011"]

# R1...........

# Apply the S-box substitution to the plaintext
substituted_plaintext1 = [S_box[int(cell, 2)] for cell in plaintext]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext1 = Mixcolumn(substituted_plaintext1)


# Apply the shuffle operation using tao
shuffled_plaintext1 = [mixed_plaintext1[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext1 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext1)]


#R2........

# Apply the S-box substitution to the plaintext
substituted_plaintext2 = [S_box[int(cell, 2)] for cell in ciphertext1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext2 = Mixcolumn(substituted_plaintext2)


# Apply the shuffle operation using tao
shuffled_plaintext2 = [mixed_plaintext2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext2 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext2)]

#S......

# Apply the S-box substitution to the plaintext
substituted_plaintext3 = [S_box[int(cell, 2)] for cell in ciphertext2]



# XOR the encryption key to get the ciphertext
ciphertext3 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(substituted_plaintext3)]



# Print the ciphertext
print("Ciphertext3:", "".join(ciphertext3))


# Collection of faulty ciphertexts:
# Original Ciphertext3: 1101 1110 1100 0100 \0111 0011 0101 1110 \0011 1101 0001 0111 \1001 0100 1100 1111                   0101     Ciphertext3: 0110 0110 1100 0001 \0101 1001 1010 1110 \0011 1101 0001 0111 \0100 0100 0001 0011
# 1100     Ciphertext3: 1011 0010 1100 0101 \0011 0010 0110 1110 \0011 1101 0001 0111 \1110 0100 1111 0000                   

# In[7]:


# Unique key recovery of L1 of QARMAv2-64 

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

#########################################################################################################
# unique key recovery of k0,k5 and k15
# Define the Eqn. (3) as in paper:

def equation_valid(c0, c5, c15, d0, d5, d15):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k5 in k_values :
         for k0, k15 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c15, 2) ^ int(k15, 2), '04b')), 2) ^ int(s(format(int(d15, 2) ^ int(k15, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c5, 2) ^ int(k5, 2), '04b')), 2) ^ int(s(format(int(d5, 2) ^ int(k5, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c0, 2) ^ int(k0, 2), '04b')), 2) ^ int(s(format(int(d0, 2) ^ int(k0, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k0 , k5 , k15))
    return valid_keys           

# Input values for fault 0101
c0 = '1101'
c5 = '0011'
c15 = '1111'
d0 = '0110'
d5 = '1001'                                                       
d15 = '0011'

# Check for valid values of keys
valid_keys_set1 = equation_valid(c0, c5, c15, d0, d5, d15)


# Input values for second set for fault 1100
c0 = '1101'
c5 = '0011'
c15 = '1111'
d0 = '1011'
d5 = '0010'                                                       
d15 = '0000'

# Check for valid values of keys
valid_keys_set2 = equation_valid(c0, c5, c15, d0, d5, d15)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("Common Keys: k0,k5,k15")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

#########################################################################################################
# unique key recovery of k3,k6 and k12
# Define the Eqn. (3) as in paper:

def equation_valid(c3, c6, c12, d3, d6, d12):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k6 in k_values :
         for k3, k12 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c12, 2) ^ int(k12, 2), '04b')), 2) ^ int(s(format(int(d12, 2) ^ int(k12, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c6, 2) ^ int(k6, 2), '04b')), 2) ^ int(s(format(int(d6, 2) ^ int(k6, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c3, 2) ^ int(k3, 2), '04b')), 2) ^ int(s(format(int(d3, 2) ^ int(k3, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k3 , k6 , k12))
    return valid_keys           

# Input values for fault 0101
c3 = '0100'
c6 = '0101'
c12 = '1001'
d3 = '0001'
d6 = '1010'                                                       
d12 = '0100'

# Check for valid values of keys
valid_keys_set1 = equation_valid(c3, c6, c12, d3, d6, d12)


# Input values for second set for fault 1100
c3 = '0100'
c6 = '0101'
c12 = '1001'
d3 = '0101'
d6 = '0110'                                                       
d12 = '1110'

# Check for valid values of keys
valid_keys_set2 = equation_valid(c3, c6, c12, d3, d6, d12)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("\n Common Keys: k3,k6,k12")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    

#########################################################################################################
# unique key recovery of k6,k9 and k12
# Define the Eqn. (2) as in paper:

def equation_valid(c1, c4, c14, d1, d4, d14):
    k_values = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111', '1000', '1001', '1010', '1011', '1100', '1101', '1110', '1111']
    
    valid_keys = set()
    for k1 in k_values :
         for k4, k14 in itertools.product(k_values, repeat=2):
            left_side1 = format(int(rho(format((int(s(format(int(c14, 2) ^ int(k14, 2), '04b')), 2) ^ int(s(format(int(d14, 2) ^ int(k14, 2), '04b')), 2)),'04b')),2),'04b')
            right_side = format((int(s(format(int(c1, 2) ^ int(k1, 2), '04b')), 2) ^ int(s(format(int(d1, 2) ^ int(k1, 2), '04b')), 2)),'04b')
            left_side2 = format(int(rho(rho(format((int(s(format(int(c4, 2) ^ int(k4, 2), '04b')), 2) ^ int(s(format(int(d4, 2) ^ int(k4, 2), '04b')), 2)),'04b'))),2),'04b')
            if left_side1 == right_side and left_side2 == right_side:
                valid_keys.add((k1 , k4 , k14))
    return valid_keys           

# Input values for fault 0101
c1 = '1110'
c4 = '0111'
c14 = '1100'
d1 = '0110'
d4 = '0101'                                                       
d14 = '0001'

# Check for valid values of keys
valid_keys_set1 = equation_valid(c1, c4, c14, d1, d4, d14)


# Input values for second set for fault 1100
c1 = '1110'
c4 = '0111'
c14 = '1100'
d1 = '0010'
d4 = '0011'                                                       
d14 = '1111'

# Check for valid values of keys
valid_keys_set2 = equation_valid(c1, c4, c14, d1, d4, d14)

# Find the common intersection of keys for both sets
common_keys = valid_keys_set1.intersection(valid_keys_set2)

# Print the common keys
i=0;
print("\n Common Keys: k1,k4,k14")
for key in common_keys:
    i += 1
    print(f" {i}")
    print(key)
    


# In[ ]:




