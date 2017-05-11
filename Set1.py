## CRYPTOPALS SET 1
## https://cryptopals.com/sets/1




## Challenge 1

def ch1():
    import base64
    x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    x = x.decode("hex")
    print x
    print base64.b64encode(x)

## Challenge 2

def ch2():
    x = "1c0111001f010100061a024b53535009181c"
    y = "686974207468652062756c6c277320657965"
    
    x = int(x,base=16)
    y = int(y,base=16)
    # x = x.decode("hex")
    # y = y.decode("hex")
    
    # print x
    # print y
    z = y ^ x
    # hex(z)
    print hex(z)

def ch3():
    import re
    x = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    # x = int(x,base=16)
    x = x.decode('hex')
    x = [ord(i) for i in x]
    
    wordfile = open("commonwords.txt","r")
    wordlist = wordfile.read().split("\n")
    for word in wordlist: 
        if word == '': 
            wordlist.remove(word)
    # print wordlist
    wordfile.close()

    words_results = []
    characters_results = []

    ## CHECKING BY WORDS (much slower)
    # for key in range(256):
    #     result = [chr(i ^ key) for i in x]
    #     for word in wordlist:
    #         if re.search(word,''.join(result)):
    #             print str(key)+" produces '"+''.join(result)+"' for matching '"+word+"'"
    
    nums = [24,56,88,120,152,184]
    specialnums = [34,99]

    # CHECKING BY CHARACTERS (much faster)
    score = 0.0
    for key in range(256):
    # for key in specialnums:
    # for key in nums:
        tempscore = 0
        result = [chr(i ^ key) for i in x]
        joinedresult = ''.join(result)
        for i in joinedresult:
            if 'a'<=i<='z' or 'A'<=i<='Z':
                # characters_results += []
                tempscore+=1
        tempscore = float(tempscore) / len(joinedresult)
        if tempscore >= score:
            score = tempscore
            print str(score)+", "+joinedresult+", "+str(key)
        ## BY LEAVING THIS LINE ON, AND ITERATING
        ## THROUGH NUMBERS 34 AND 99, '62;c' IS LEFT 
        ## IN COMMAND LINE AFTER PROGRAM FINISHES. NO
        ## OTHER NUMBERS UP TO 499 DO THIS.
        # if key == 120: #interesting coincidence
        #     print result

def altch3():
    # FOUND AT https://github.com/yuvadm/matasano-cryptopals/blob/master/set1/challenge3.py
    x = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    def score_plaintext(s):
        letters = filter(lambda x: 'a'<=x<='z' or 'A'<=x<='Z', s)
        # letters = filter('a'<=x<='z' | 'A'<=x<='Z', s) #doesn't work for bool 'or'
        return float(len(letters)) / len(s)

    def get_max_single_char_xor(s):
        res = []
        for i in range(256):
            # print "trying "+str(i)
            chrs = [chr(ord(s) ^ i) for s in x.decode('hex')]
            res.append([score_plaintext(chrs), ''.join(chrs),i])
        return max(res, key=lambda x: x[0])

    if __name__ == '__main__':
        print get_max_single_char_xor(x)

def ch4():
    encryptionsdoc = open("ch4.txt","r")
    strings = encryptionsdoc.read().split("\n")

    decryptedstrings = []
    for i in strings:
        decryptedstrings += [i.decode("hex")]

    score = 0.0
    for i in range(256):
        for string in decryptedstrings:
            tempscore = 0.0
            newstring = [chr(ord(char) ^ i) for char in string]
            newstring = ''.join(newstring)
            for c in newstring:
                if 'a'<=c<='z' or 'A'<=c<='Z' or c == ' ':
                    tempscore += 1
                    oldtempscore = tempscore
            tempscore = float(tempscore) / float(len(newstring))
            if tempscore >= score:
                score = tempscore
                print "------------------------"
                print str(score)+", key: "+str(i)
                print strings[decryptedstrings.index(string)] #neater than string
                # print string
                print newstring
                print oldtempscore
    print "------------------------"
            
def ch5():
    message = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    # message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    expectedresult = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    ordmessage = [ord(i) for i in message]
    ordkey = [ord(i) for i in key]
    # print ordmessage
    keycount = 0
    encryptedmessage = []
    for character in ordmessage:
        # encryptedmessage += format([character ^ ordkey[keycount]],'x')
        encryptedmessage += [character ^ ordkey[keycount]]
        if keycount == 2:
            keycount = 0
        else:
            keycount += 1
    # print encryptedmessage

    # a = [ord(i) for i in expectedresult.decode("hex")]
    # print a

    hexedmessage = []
    for i in encryptedmessage:
        hexedmessage += '{:02x}'.format(i,'x') # parameter 'x' at end is redundant for {:02x} 
    # print expectedresult
    # print hexedmessage
    print ''.join(hexedmessage)
    # print ''.join(encryptedmessage)

def ch6():
    import base64
    
    encryptedfile = open("ch6.txt","r")
    encryptedmessage = encryptedfile.read()
    encryptedfile.close()
    encryptedmessage = base64.b64decode(encryptedmessage)
    # print encryptedmessage
    keysize = range(2,41)

    def finddistance(input1, input2): # Hemming Distance
        # input1 = "this is a test"
        # input2 = "wokka wokka!!!" ## distance should be 37
        ## convert input string chars to binary string
        input1 = ''.join(['{:08b}'.format(ord(i),'b') for i in input1]) ## 'b' in (ord(i),'b') is redundant for {:08b} 
        input2 = ''.join(['{:08b}'.format(ord(i),'b') for i in input2]) ## {:08b} means to make a string that is 8 chars long, ascii to bytes 
        ## int converts binary string to base 10 number(long) for xor'ing, format converts result to binary, then lists bits.
        result = list(format(int(input1,base=2) ^ int(input2,base=2),'b'))
        ## adds up the list of bits
        distance = sum([int(i) for i in result])
        # print distance
        return distance
    
    keysizeresults = {}
    # print keysize
    for size in keysize:
        # print size
        #take first 2 sets of bytes, equal in size to 'size', find hemming distance, divide by 'size'
        #distance from finddistance() is 'normalized' by dividing it by size
        thedistance = float(finddistance(encryptedmessage[0:size],encryptedmessage[size:size*2]))/float(size)
        ## keysize and distance are added to dict
        keysizeresults[thedistance] = size
    # print keysizeresults

    probablekeysizes = []
    ## sort least to greatest by key (distance) and display least 3
    for i in sorted(keysizeresults.keys())[0:3]:
        print "keysize "+str(keysizeresults[i])+" with distance "+str(i)
        probablekeysizes += [keysizeresults[i]]
    print
    keychars = dict()

    for size in probablekeysizes:
        keychars[size] = []
        print "--------------------"
        print "trying key size "+str(size)+":"
        ## break encrypted message into blocks of likely keysizes (size)
        blockedmessage = [encryptedmessage[i:i+size] for i in range(0,len(encryptedmessage),size)]
        # print blockedmessage
        ## create new blocks from first byte of each block, then 2nd byte of each block, etc.
        j, newblockedmessage = 0, []
        while j < size:
            # print "blocked message len = "+str(len(blockedmessage))
            # print "blocked message type is "+str(type(blockedmessage))
            # print "j = "+str(j)
            # for block in blockedmessage:
            #     newblockedmessage += [''.join([i[j]]) for ]
            tempchars = []
            for block in blockedmessage:
                try:
                    tempchars.append(block[j])
                except IndexError:
                    print "index error at index "+str(blockedmessage.index(block))+" out of "+str(len(blockedmessage)-1)
            newblockedmessage.append(''.join(tempchars))
            # print newblockedmessage
            j += 1

        ## scoring single-byte xor decrypting for each new block from ch4() above
        for block in newblockedmessage:
            score = 0.0
            temprecord = []
            for i in range(256):
                tempscore = 0.0
                newstring = ''.join([chr(ord(char) ^ i) for char in block])
                for c in newstring:
                    if 'a'<=c<='z' or 'A'<=c<='Z' or c == ' ':
                        tempscore += 1
                        oldtempscore = tempscore
                tempscore = float(tempscore) / float(len(newstring))
                if tempscore >= score:
                    score = tempscore
                    temprecord = [chr(i),newblockedmessage.index(block), tempscore]
            keychars[size].append(temprecord)
            ## Display results
        print "\nFor keysize "+str(size)+":"
        for letter in keychars[size]:
            print "Letter "+letter[0]+" at position "+str(letter[1])+" with score "+str(letter[2])
    print "--------------------"




        

## ACTIVE CHALLENGE FUNCTION
    
# ch1()
# ch2()
# ch3()
# altch3()
# ch4()
# ch5()
# ch6()

import binascii
import sys
import base64
import re
from random import randint

MAXINT = 10000

def strHamming(s1, s2):
	difCnt = 0
	for i in range(0, len(s1)):
		if s1[i] != s2[i]:
			difCnt += 1
	return difCnt


def bin8(c):
	return bin(ord(c))[2:].zfill(8)


def binHamming(s1, s2):
	n = len(s1)
	s1bin = ""
	for c in s1:
		s1bin += bin8(c)
	
	s2bin = ""
	for c in s2:
		s2bin += bin8(c)

	difCnt = 0
	for i in range(0, len(s1bin)):		
		if s1bin[i] != s2bin[i]:
			difCnt += 1
	return difCnt


def min2(a, b):
	if a < b:
		return a
	return b


def find_key_size(data):	
	print "=================== FIND KEY SIZE ==================="	
	n = len(data)
	minkeysize = MAXINT
	minkey = -1
	for keysize in range(2, min2(n/2, 35)):		
		
		p = []
		for i in range(1, n/keysize+1):						
			p.append(data[keysize*(i-1):keysize*i])			

		sumHammingDistance = 0		
		cntrepeated = 10000		
		for i in range(0, 10000):			
			first = p[randint(0, len(p)-1)]
			second = p[randint(0, len(p)-1)]			
			sumHammingDistance += float(binHamming(first, second) / keysize)								

		print keysize, sumHammingDistance / cntrepeated

		if sumHammingDistance / cntrepeated < minkeysize:
			minkeysize = sumHammingDistance / cntrepeated
			minkey = keysize
	return minkey


def is_prinable(r):
	return (r == 10) or (32 <= r < 128)	


def find_key(keysize, data):
	print "=================== FIND KEY ==================="	
	blocks = re.findall('.'*keysize*2, data)	
	
	key = ''

	for ikey in range(0, keysize):		# Find key character at position ikey
		print "Key[" + str(ikey) + "] = ",
		for i in range(10, 128):		# Try all posible of key char, which is prinable. You can expand it
			keychar = chr(i)		
			ok = 0	

			for block in blocks:			
				block = block.decode('hex')				
				r = ord(block[ikey]) ^ ord(keychar)				
				if is_prinable(r):			
					ok += 1						
			if len(blocks) - ok == 0:						
				print '[' + keychar + ']', 
				
		print ''


def main():
	f = open("ch6.txt", "r")
	data = f.read()
	f.close()
	data = base64.b64decode(data).encode('hex') 				
	
	keySize = find_key_size(data)
	keysize = 29
	print "Keysize = " + str(keysize)	
	

	find_key(keysize, data)
					

if __name__ == '__main__':
    main()