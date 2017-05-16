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
    
    # wordfile = open("commonwords.txt","r")
    # wordlist = wordfile.read().split("\n")
    # for word in wordlist: 
    #     if word == '': 
    #         wordlist.remove(word)
    # # print wordlist
    # wordfile.close()

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

    # a = [ord(i) for i in expectedresult.decode("hex")]
    # print a

    hexedmessage = []
    for i in encryptedmessage:
        hexedmessage += '{:02x}'.format(i,'x') # parameter 'x' at end is redundant for {:02x} 
    # print expectedresult
    # print hexedmessage
    print ''.join(hexedmessage)

def ch6():
    print
    import base64
    
    encryptedfile = open("ch6.txt","r")
    encryptedmessage = encryptedfile.read()
    encryptedfile.close()
    encryptedmessage = base64.b64decode(encryptedmessage)
    keysize = range(2,40)

    def finddistance(input1, input2): # Hemming Distance
        ## convert input string chars to binary string
        input1 = ''.join(['{:08b}'.format(ord(i),'b') for i in input1]) ## 'b' in (ord(i),'b') is redundant for {:08b} 
        input2 = ''.join(['{:08b}'.format(ord(i),'b') for i in input2]) ## {:08b} means to make a string that is 8 chars long, ascii to bytes 
        ## int converts binary string to base 10 number(long) for xor'ing, format converts result to binary, then lists bits.
        try:
            result = list(format(int(input1,base=2) ^ int(input2,base=2),'b'))
        except ValueError: ## If the encrypted message is too short for the current loop and input2 has nothing
            return
        ## adds up the list of bits
        distance = sum([int(i) for i in result])
        return distance

    keysizeresults = {}
    for size in keysize:
        ## take first 2 sets of bytes, equal in size to 'size', find hemming distance
        ## repeat many times, add the distances together, divide by number of distance, then divide by 'size'
        ## distance from finddistance() is 'normalized' by dividing it by size
        d = []
        for i in range (0,100):
            try:
                d.append(float(finddistance(encryptedmessage[size*i:size*(i+1)],encryptedmessage[size*(i+1):size*(i+2)])))
            except TypeError: ## If the encrypted message is too short for the current loop and input2 has nothing
                # print "2nd keysize block empty while trying keysize "+str(size)+"."
                break
        thedistance = sum(d)/float(size)/(len(d))
        ## keysize and distance are added to dict
        keysizeresults[thedistance] = size

    probablekeysizes = []
    ## sort least to greatest by key (distance) and display least 3
    for i in sorted(keysizeresults.keys())[0:4]:
        print "keysize "+str(keysizeresults[i])+" with distance "+str(i)
        probablekeysizes += [keysizeresults[i]]
    print
    keychars = dict()
    
    ## Using the likely sizes, found the likeliest chars for each size then score each potential key
    for size in probablekeysizes:
        keychars[size] = []
        print "\n--------------------\n"
        print "trying key size "+str(size)+"..."
        ## Break encrypted message into blocks of likely keysizes (size)
        blockedmessage = [encryptedmessage[i:i+size] for i in range(0,len(encryptedmessage),size)]
        ## create new blocks from first byte of each block, then 2nd byte of each block, etc.
        j, newblockedmessage = 0, []
        errorraised = 0
        while j < size:
            tempchars = []
            for block in blockedmessage:
                try:
                    tempchars.append(block[j])
                except IndexError:
                    if errorraised == 0:
                        print "index error at index "+str(blockedmessage.index(block))+" out of "+str(len(blockedmessage)-1)
                        errorraised = 1
            newblockedmessage.append(''.join(tempchars))
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
        print "\nFor keysize "+str(size)+":"
        averagescore = 0.0
        for letter in keychars[size]:
            print "Letter "+letter[0]+" at position "+str(letter[1])+" with score "+str(letter[2])
            averagescore += letter[2]
        averagescore = averagescore/size
        keychars[size].append(averagescore)

    themax = max([keychars[i][i] for i in keychars.iterkeys()]) ## get highest average score among keysizes 
    for i in keychars.iterkeys():
        if keychars[i][i] == themax:
            print "\n****************************************************"
            print "The key is probably:"
            thekey = ''.join([keychars[i][j][0] for j in range(0,i)])
            print "---> "+thekey+" <---"
            print "With average score: "+str(keychars[i][i])
            print "****************************************************\n"

    ## Use key to decrypt and display message
    ordkey = [ord(i) for i in thekey]
    ordmessage = [ord(i) for i in encryptedmessage]
    keycount = 0
    decryptedmessage = ""
    for c in ordmessage:
        decryptedmessage += str(chr(c ^ ordkey[keycount]))
        keycount += 1
        if keycount == len(ordkey):
            keycount = 0

    print decryptedmessage
    print "\n****************************************************\n"

def ch7():
    import base64
    thefile = open('ch7.txt','r')
    thetext = thefile.read()
    encryptedmessage = base64.b64decode(thetext)
    thefile.close()

    from Crypto.Cipher import AES
    key = b'YELLOW SUBMARINE'
    cipher = AES.new(key, AES.MODE_ECB)
    print cipher.decrypt(encryptedmessage)

def ch8():
    textfile = open('ch8.txt','r')
    thetext = textfile.read().split('\n')
    thetext = [i.decode("hex") for i in thetext]
    if '' in thetext: thetext.remove('')
    textfile.close()
    # print thetext

    from Crypto.Cipher import AES
    key = "sixteen byte key"
    cipher = AES.new(key, AES.MODE_ECB)
    ECBstrings = []
    for item in thetext:
        # print "Trying index "+str(thetext.index(i))
        # print cipher.decrypt(i)
        string = [item[j:j+16] for j in range(0,len(item),16)]
        if set([block for block in string if string.count(block) > 1]) == set([]):
            pass
        else:
            ECBstrings.append([thetext.index(item),item.encode("hex")])
    print
    print "*************************"
    for i in ECBstrings:
        print "String "+str(i[0])+" seems to be ECB."
        print i[1]
        print "*************************" 

    


## ACTIVE CHALLENGE FUNCTION
    
# ch1()
# ch2()
# ch3()
# altch3()
# ch4()
# ch5()
# ch6()
# ch7()
ch8()
