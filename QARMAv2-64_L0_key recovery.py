#!/usr/bin/env python
# coding: utf-8

# L0 key Recovery of QARMAv2-64

# In[21]:


#True ciphertext generation for (r-1)th backward round attack

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

# Print the ciphertext
print("Ciphertext2(r-1):", "".join(ciphertext2))




# In[22]:


#faulty ciphertext generation with a random fault at 0th position before round r-1
# let the random fault value be  0111

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

plaintext = ["1101", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
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


# Print the ciphertext
print("Ciphertext2(r-1,0)(0111):", "".join(ciphertext2))


# In[23]:


#faulty ciphertext generation with a random fault at 0th position before round r-1
#Let the fault value be 1001

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

    
plaintext = ["0011", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
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

# Print the ciphertext
print("Ciphertext2(r-1,0)(1001):", "".join(ciphertext2))


# In[24]:


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


# Print the ciphertext
print("Ciphertext2(r-1,1)(0101):", "".join(ciphertext2))


# In[25]:


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


# Print the ciphertext
print("Ciphertext2(r-1,1)(1100):", "".join(ciphertext2))


# In[26]:


#True ciphertext generation for (r-2)th backward round attack

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
ciphertext1 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext1)]


#R2........

# Apply the S-box substitution to the plaintext
substituted_plaintext2 = [S_box[int(cell, 2)] for cell in ciphertext1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext2 = Mixcolumn(substituted_plaintext2)


# Apply the shuffle operation using tao
shuffled_plaintext2 = [mixed_plaintext2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext2 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext2)]


#R3........

# Apply the S-box substitution to the plaintext
substituted_plaintext3 = [S_box[int(cell, 2)] for cell in ciphertext2]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext3 = Mixcolumn(substituted_plaintext3)


# Apply the shuffle operation using tao
shuffled_plaintext3 = [mixed_plaintext3[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext3 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext3)]


# Print the ciphertext
print("Ciphertext3(r-2):", "".join(ciphertext3))




# In[27]:


#faulty ciphertext generation with a random fault at 0th position before round r-2
#Let the fault value be 1110

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
plaintext = ["0100", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
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
ciphertext1 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext1)]


#R2........

# Apply the S-box substitution to the plaintext
substituted_plaintext2 = [S_box[int(cell, 2)] for cell in ciphertext1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext2 = Mixcolumn(substituted_plaintext2)


# Apply the shuffle operation using tao
shuffled_plaintext2 = [mixed_plaintext2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext2 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext2)]


#R3........

# Apply the S-box substitution to the plaintext
substituted_plaintext3 = [S_box[int(cell, 2)] for cell in ciphertext2]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext3 = Mixcolumn(substituted_plaintext3)


# Apply the shuffle operation using tao
shuffled_plaintext3 = [mixed_plaintext3[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext3 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext3)]


# Print the ciphertext
print("Ciphertext3(r-2,0)(1110):", "".join(ciphertext3))




# In[28]:


#faulty ciphertext generation with a random fault at 0th position before round r-2
#Let the fault value be 0011

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
plaintext = ["1001", "0111", "1001", "1011", "1100", "0110", "1110", "1111",
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
ciphertext1 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext1)]


#R2........

# Apply the S-box substitution to the plaintext
substituted_plaintext2 = [S_box[int(cell, 2)] for cell in ciphertext1]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext2 = Mixcolumn(substituted_plaintext2)


# Apply the shuffle operation using tao
shuffled_plaintext2 = [mixed_plaintext2[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext2 = [format(int(cell, 2) ^ int(key1[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext2)]


#R3........

# Apply the S-box substitution to the plaintext
substituted_plaintext3 = [S_box[int(cell, 2)] for cell in ciphertext2]


# Apply the Mixcolumn operation to the substituted plaintext
mixed_plaintext3 = Mixcolumn(substituted_plaintext3)


# Apply the shuffle operation using tao
shuffled_plaintext3 = [mixed_plaintext3[i] for i in tao]


# XOR the shuffled plaintext with the encryption key to get the ciphertext
ciphertext3 = [format(int(cell, 2) ^ int(key0[i], 2), '04b') for i, cell in enumerate(shuffled_plaintext3)]


# Print the ciphertext
print("Ciphertext3(r-2,0)(0011):", "".join(ciphertext3))




#                             0    1    2    3     4    5    6    7     8    9   10   11    12   13   14   15
# Ciphertext2(r-1):         0111 1011 1001 1101 \1111 1001 1111 0011 \1111 0000 1111 0100 \0111 0011 1110 1100
# Ciphertext2(r-1,0)(0111): 0111 1011 1001 1101 \1001 1001 1011 0001 \1110 1000 1111 0111 \0101 0111 0010 1100
# Ciphertext2(r-1,0)(1001): 0111 1011 1001 1101 \0111 1001 1100 1111 \1001 0110 1111 0000 \1110 1010 1111 1100
# Ciphertext2(r-1,1)(0101): 0001 1101 1001 0010 \0110 0000 0000 0011 \1111 0000 1111 0100 \1000 0011 1101 0000
# Ciphertext2(r-1,1)(1100): 1111 1010 1001 0001 \1011 1011 1100 0011 \1111 0000 1111 0100 \1110 0011 0110 1101
# 

#                             0    1    2    3     4    5    6    7     8    9   10   11    12   13   14   15
# Ciphertext3(r-2):         0011 0100 0010 0101 \0110 0000 0010 1101 \1011 1011 0000 0001 \0011 1011 1001 1011
# Ciphertext3(r-2,0)(1110): 0100 0100 0011 1101 \1000 0111 0000 1100 \0001 0010 0001 0001 \0100 0011 0100 0100
# Ciphertext3(r-2,0)(0011): 1010 1000 1010 1110 \1101 1011 1100 0000 \0100 1100 1000 1000 \1001 1111 1000 0100
