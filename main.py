import hmac
import hashlib
import random

# bitwise XOR function operating on two byte sequences (multiple Bytes each)
# If the argument have different number of bytes, it will return a result that 
# is as long as the shorter argument. 
def xor(byteseq1, byteseq2):
    # First we convert each byte to its int value
    l1 = [b for b in byteseq1]
    l2 = [b for b in byteseq2]

    # Then we use the xor ^ operator to xor the integer values
    # At the same time, we convert the resulting intergers back to byte form
    # Note that the zip function automatically picks the size of the shorter of l1,l2
    # so l1xorl2 is the same size as the shorter of l1 and l2. This allows us to 
    # select our F function to always give a long output even if we need part of it.
    l1xorl2 = [bytes([elem1^elem2]) for elem1,elem2 in zip(l1,l2)]
    
    # finally, we convert the list of individual XOR results into a byte sequence
    # by concatenating all of them together
    result = b''.join(l1xorl2)

    return result

# As discussed, round function F can be any arbitrary function but it's usually a shuffling function
# such as a hash function. Here we use the SHA1 hash (we'll study the details of it later)
# to create a function that returns a 32bit string (since we assume 32 bit byteseq input)
def F(byteseq, k):
    # create a hmac sha1 
    h = hmac.new(k, byteseq, hashlib.sha1)
    # Return first 8 bytes of the calculated hmac sha1 hash

    #print("F: encoding:")
    #print(k)
    #print(byteseq)
    #print(h.digest()[:8])

    return h.digest()[:8]

# main block processing
def feistel_block(LE_inp, RE_inp, k):
    # LEinp and REinp are the outputs of the previous round
    # k is the key for this round which usually has a different 
    # value for different rounds

  # test:
  #print(LE_inp)
  #F(str(LE_inp).encode(), k)

  #LE_out = "placeholderLE"
  #RE_out = "placeholderRE"

  # left becomes processed version of Right 
  RHS = xor(LE_inp, F(RE_inp, k))

  # right becomes what was original left
  LHS = RE_inp

  LE_out = LHS
  RE_out = RHS
      
  return LE_out, RE_out
    

# In a real Feistel implementation, different keys are used in different rounds. Here
# we use 64bit keys so for 16 rounds, we need 16 random 8byte keys. We can just generate
# 16 random 8 byte numbers we use the random.randint() function to be able to set the seed
# value and create the same keys for both the encoder and the decoder
def gen_keylist(keylenbytes, numkeys, seed):
    # We need to generate numkeys keys each being keylen bytes long
    keylist = []
    random.seed(seed)

    #print("numkeys " )
    #print(numkeys)

    # 16 random byte sequences, 4 bytes each; one byte is 256 different possible values so (4*256)-1 = 1023
    #maxrange = ((keylenbytes//2)*256) - 1

    '''
    for key in range(numkeys):
      intkey = random.randint(0, maxrange)
      bytekey = intkey.to_bytes(4, byteorder="little")
      keylist.append(bytekey)
      #keylist.append(bytes(intkey))
      print(intkey)
      print(bytekey)'''

    for key in range(numkeys):
      #intkey = random.randint(0, 254)

      bytechunk = bytes([random.randint(0, 254)]) + bytes([random.randint(0, 254)]) + bytes([random.randint(0, 254)]) + bytes([random.randint(0, 254)])

      keylist.append(bytechunk)
  
      #print("key " + str(key) + ": " + str(bytechunk))  
    
    # Use the random.randint(min,max) function to generate individual
    # random integers in range [min, max]. Generate a list of 16
    # random byte sequences each of the 4 bytes long to be used as 
    # keys for 16 stages of the feistel encoder. 

    #To make sure we have control over
    # the generated random numbers meaning that the same sequence is 
    # generated in different runs of our program, 
    
    # keylist = [16 elements of 'bytes' type and 4 bytes long each]
    
    return keylist


def feistel_enc(inputblock, num_rounds, seed):
    # This is the function that accepts one block of plaintext
    # and applies all rounds of the feistel cipher and returns the
    # cipher text block. 
    # Inputs:
    # inputblock: byte sequence representing input block
    # num_rounds: integer representing number of rounds in the feistel 
    # seed: integer to set the random number generator to defined state
    # Output:
    # cipherblock: byte sequence
    
    # first generate the required keys
    keylist = gen_keylist(8, num_rounds, seed)
    
    #print(keylist)

    LE_inp = [""] * (num_rounds+1)
    RE_inp = [""] * (num_rounds+1)

    blocksize = len(inputblock)

    #print(type(inputblock))

    LE_inp[0] = inputblock[:int(blocksize/2)]
    RE_inp[0] = inputblock[int(blocksize/2):int(blocksize)]

    for round in range(1, num_rounds+1):
      #print("ENC round ")
      #print(round)
      LE_inp[round], RE_inp[round] = feistel_block(LE_inp[round-1], RE_inp[round-1], keylist[round-1])
      
      #print(LE_inp + RE_inp)
    
    # we run this for num_rounds, then want the result of the last round
    cipherblock = RE_inp[num_rounds] + LE_inp[num_rounds]
    
    #print(cipherblock)
    
    return cipherblock

    
def feistel_enc_test(input_fname, seed, num_rounds, output_fname):
    
    # First read the contents of the input file as a byte sequence
    finp = open(input_fname, 'rb')
    inpbyteseq = finp.read()
    finp.close()
    
    # Then break the inpbyteseq into blocks of 8 bytes long and 
    # put them in a list
    blocksize = 8


    blocklist = [inpbyteseq[i: i + blocksize] for i in range(0, len(inpbyteseq), blocksize)]

    #print(len(blocklist))
    #print(blocklist)
    #print(len(blocklist[-1]))
 
    # Pad the last element with spaces b'\x20' until it is 8 bytes long
    #print(len(blocklist[-1])%8)
    if len(blocklist[-1])%8 > 0:
      blocklist[-1] = blocklist[-1] + b'\x20'*(8 - len(blocklist[-1])%8)
      

    #print(blocklist)
    # blocklist = [list of 8 byte long blocks]
    # Loop over al blocks and use the feistel_enc to generate the cipher block

    encodedlist = []

    for inputblock in blocklist:
      # this returns something, add it to a list to be joined later
      #print("processing:")
      #print(inputblock)
      #print('\n')
      encodedlist.append(feistel_enc(inputblock, num_rounds, seed))

    # append all cipherblocks together to form the output byte sequence

    cipherbyteseq = b''.join(encodedlist)

    #print("Encoded: ")
    #print(str(cipherbyteseq))

    # cipherbyteseq = b''.join([list of cipher blocks])
    
    # write the cipherbyteseq to output file

    #placeholder = b"tes32u43847138941t"
    #cipherbyteseq = placeholder.decode().split(":")[1]
    #cipherbyteseq = b"terueryuiweyruiewyrw"

    fout = open(output_fname, 'wb')
    fout.write(cipherbyteseq)
    fout.close()
    
    
def feistel_dec(inputblock, num_rounds, seed):
    # This is the function that accepts one block of ciphertext
    # and applies all rounds of the feistel cipher decruption and returns the
    # plain text block. 
    # Inputs:
    # inputblock: byte sequence representing input block
    # num_rounds: integer representing number of rounds in the feistel 
    # seed: integer to set the random number generator to defined state
    # Output:
    # cipherblock: byte sequence
    
    # first generate the required keys
    keylist = gen_keylist(8, num_rounds, seed)
    #print('\n')

    LE_inp = [""] * (num_rounds + 1)
    RE_inp = [""] * (num_rounds + 1)

    blocksize = len(inputblock)

    #print("blocksize = " + str(blocksize))
    # back that math up:

    LE_inp[num_rounds] = inputblock[:int(blocksize/2)]
    RE_inp[num_rounds] = inputblock[int(blocksize/2):int(blocksize)]


    # verify keys -- they only go from 0-15
    #print("the keys:")
    #print(keylist)
    #for round in range(0, num_rounds):
      #print("real key:")
      #print(round)
      #print(keylist[round])

    '''
    for round in range(1, num_rounds+1):
      #print("round ")
      #print(round)
      LE_inp[round], RE_inp[round] = feistel_block(LE_inp[round-1], RE_inp[round-1], keylist[round-1])
      
      #print(LE_inp + RE_inp)
    
    # we run this for num_rounds, then want the result of the last round
    cipherblock = LE_inp[num_rounds] + RE_inp[num_rounds]
    
    #print(cipherblock)
    
    return cipherblock
    '''
 
    for round in range(num_rounds, 0, -1):
      #print("DEC round " + str(round) + "/" + str(num_rounds))

      #print("key " + str(round-1) + ": " + str(keylist[round-1]))
      
      #print("L: " + str(LE_inp[round]) )
      #print("R: " + str(RE_inp[round]) )
      #print('\n')

      #if(round >1 ):
      LE_inp[round - 1], RE_inp[round - 1] = feistel_block(LE_inp[round], RE_inp[round],  keylist[round - 1])
        
        
      #else:
        #print("last round reached")
        #LE_inp[0], RE_inp[0]  = feistel_block(LE_inp[round], RE_inp[round],  keylist[0])
        
        
      '''
      #LE_inp[round - 1] = RE_inp[round]

      # trying: flipped function parameters passed
      # issue: these dont "take" (LHS is the same every round)
      
      if(round > 1):
        LE_inp[round - 1], RE_inp[round - 1] = feistel_block(RE_inp[round], LE_inp[round],  keylist[round - 1])
      else:
        print("last round reached")
        LE_inp[0], RE_inp[0]  = feistel_block(RE_inp[round], LE_inp[round],  keylist[0])
        
    '''
    #print(LE_inp[0])
    cipherblock = RE_inp[0] + LE_inp[0]


    #decodeblock = LE_inp[0] + RE_inp[0]
      #LE_inp[round], RE_inp[round] = 
      #if round == 0:
      #  LE_inp[round - 1], RE_inp[round - 1 ] = feistel_block(LE_inp[round], RE_inp[round], keylist[0])

      #else:
      #LE_inp[round - 1], RE_inp[round - 1 ] = feistel_block(LE_inp[round], RE_inp[round], keylist[round-1])
      
    #print("prefinal:")
    #print(decodeblock)
    #print((LE_inp + RE_inp).decode("utf-8") )
  
    #print('\n')
    #print(RE_inp)
    #print('\n')
    #print(LE_inp)


    # we run this for num_rounds, then want the result of the last round
    #remove comment later!!
    
    
    #print("cipherblock: ")
    #print(cipherblock)

 

    #decodeblock = cipherblock
    
    plainblock = cipherblock
    
    return plainblock

def feistel_dec_test(input_fname, seed, num_rounds, output_fname):
    
    # First read the contents of the input file as a byte sequence
    finp = open(input_fname, 'rb')
    inpbyteseq = finp.read()
    finp.close()
    
    # Then break the inpbyteseq into blocks of 8 bytes long and 
    # put them in a list
    # Pad the last element with spaces b'\x20' until it is 8 bytes long
    # blocklist = [list of 8 byte long blocks]


    #print(inpbyteseq)

    blocksize = 8


    blocklist = [inpbyteseq[i: i + blocksize] for i in range(0, len(inpbyteseq), blocksize)]

    #print(blocklist)

    # Pad the last element with spaces b'\x20' until it is 8 bytes long
    #print(len(blocklist[-1]))
    if len(blocklist[-1])%8 > 0:
      blocklist[-1] = blocklist[-1] + b'\x20'*(8 - len(blocklist[-1])%8)

    decodedlist = []
  

    for inputblock in blocklist:
      # this returns something, add it to a list to be joined later
      #print('\n')
      #print('\n')
      #print("processing:")
      #print(inputblock)
      #print('\n')


      decodedlist.append(feistel_dec(inputblock, num_rounds, seed))
      
    #print("\n\ndecoded list: ")
    #print(str(decodedlist))
    # append all cipherblocks together to form the output byte sequence

    #print("\n\ndecoded list 2: ")
    plainbyteseq = b''.join(decodedlist)
    #print(str(plainbyteseq))
    #message += ()
    

    #REMOVE THIS BEFORE TURNING IN
    #plainbyteseq = plainbyteseq


    # Loop over al blocks and use the feistel_dec to generate the plaintext block
    # append all plainblocks together to form the output byte sequence
    # plainbyteseq = b''.join([list of plain blocks])
    
    # write the plainbyteseq to output file

    fout = open(output_fname, 'wb')
    fout.write(plainbyteseq)
    fout.close()
    

def testfunction():

  seed = 1
  numrounds = 16 # change to 16
  #print("ENCODING NOW")
  feistel_enc_test('input.txt', seed, numrounds, 'output.txt')


  #print("\n\n\n####################\nATTEMPTING TO DECODE")
  feistel_dec_test('output.txt', seed, numrounds, 'finaloutput.txt')


if __name__ == "__main__":
    testfunction()