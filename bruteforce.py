import hashlib
import io
import itertools
import string

lowerCaseChars = string.ascii_lowercase
upperCaseChars = string.ascii_uppercase
digitChars = string.digits
punctuationChars = string.punctuation

#will open the file given and extract a dictionary of the hashes, whereby each key is a hash and has value 0 unless a match is found
def createHashDictionary(fileName):
    with open(fileName, "r") as hashFile:
        HashDictionary = {}
        #will add every hash to the dictionary
        for hash in hashFile:
            strippedAndLoweredHash = hash.strip().lower()
            HashDictionary[strippedAndLoweredHash] = 0
        return HashDictionary

#will generate the SHA1 Hash for a given guess string, https://pymotw.com/2/hashlib/ used as reference
def generateSHA1Hash(guessString):
    hashObject = hashlib.sha1()
    hashObject.update(guessString)
    return hashObject.hexdigest().lower()

# def isExistHashValue(hashValue, hashDictionary):
#     if hashValue in hashDictionary:

def isExistPassword(pseudoPassword, hashDictionary):
    hashedPseudoPassword = generateSHA1Hash(pseudoPassword.encode("utf-8"))
    if hashedPseudoPassword in hashDictionary:
        hashDictionary[hashedPseudoPassword] = pseudoPassword
        print(f"{hashedPseudoPassword}: <{pseudoPassword}>")
        return True
    else:
        return False

def simpleDictionaryBruteForce(dictionary, hashDictionary):
    #this step was inspired by https://null-byte.wonderhowto.com/how-to/use-beginner-python-build-brute-force-tool-for-sha-1-hashes-0185455/
    #try and see if any of the known passwords are present
    count = 0 #incremented for each match found
    with io.open(dictionary, "r", encoding="utf-8") as pseudoPasswordList:
        for pseudoPassword in pseudoPasswordList:
            strippedPseudoPassword = pseudoPassword.rstrip()
            # hashedpseudoPassword = generateSHA1Hash(strippedPseudoPassword.encode("utf-8"))
            # print("<", strippedPseudoPassword, ">", hashedpseudoPassword)
            if isExistPassword(strippedPseudoPassword, hashDictionary):
                count += 1
    return count

def rawBruteForceHelper(length, hashDictionary, charList):
    #this step inspired by https://stackoverflow.com/questions/47952987/how-to-make-all-of-the-permutations-of-a-password-for-brute-force
    count = 0
    for pseudoPasswordTuple in itertools.product(charList, repeat=length):
        pseudoPassword = "".join(pseudoPasswordTuple)
        if isExistPassword(pseudoPassword, hashDictionary):
            count += 1
    return count

def rawBruteForce(startingLength, endingLength, hashDictionary, charList):
    totalHashesFound = 0
    for passwordLength in range(startingLength, endingLength + 1):
        hashesFound = rawBruteForceHelper(passwordLength, hashDictionary, charList)
        totalHashesFound += hashesFound
        print(f"{hashesFound} Hashes Found with raw brute force of [{charList}] of length {passwordLength}")
    return totalHashesFound

def intelligentBruteForceHelper(textualLength, textualChars, numericLength, numericChars, hashDictionary):
    count = 0
    for textTuple in itertools.product(textualChars, repeat=textualLength):
        text = "".join(textTuple)
        for numericTuple in itertools.product(numericChars, repeat=numericLength):
            number = "".join(numericTuple)
            pseudoPassword = text + number
            if isExistPassword(pseudoPassword, hashDictionary):
                count += 1
    return count


def intelligentBruteForce(startingTextualLength, endingTextualLength, textualChars, startingNumericLength, endingNumericLength, numericChars, hashDictionary):
    totalHashesFound = 0
    for textualLength in range(startingTextualLength, endingTextualLength + 1):
        for numericLength in range(startingNumericLength, endingNumericLength + 1):
            hashesFound = intelligentBruteForceHelper(textualLength, textualChars, numericLength, numericChars, hashDictionary)
            totalHashesFound += hashesFound
            print(f"{hashesFound} Hashes Found with intelligent brute force of {textualLength} characters from {textualChars}, {numericLength} from {numericChars}")



def bruteForceWrapper(hashDictionary):
    #attack of everything from 1 to 5 all ascii characters
    rawBruteForce(1, 5, hashDictionary, lowerCaseChars + upperCaseChars + digitChars + punctuationChars)
    #attack of lowercase from 1 to 7
    rawBruteForce(1, 7, hashDictionary, lowerCaseChars)
    #attack of digits from 1 to 8
    rawBruteForce(1, 8, digitChars)
    #slightly more intelligent (digits of upto length 3 added to the end of simple password consisting of only textual characters)
    intelligentBruteForce(1, 6, lowerCaseChars, 1, 3, digitChars, hashDictionary)



#this is a slow step
print("BEGIN hashDictionary making")
hashDictionary = createHashDictionary("linkedin/SHA1.txt")
print("END hashDictionary making")

print("BEGIN simpleDictionaryBruteForce")
passwordsFound = simpleDictionaryBruteForce("passwordList/rockyouAlt.txt", hashDictionary)
print("END simpleDictionaryBruteForce")

print("BEGIN PURE BRUTE FORCE")
bruteForceWrapper(hashDictionary)
print("END PURE BRUTE FORCE")

print("PASSWORDS FOUND")
crackedDict = {key:value for (key,value) in hashDictionary.items() if value != 0}
print(crackedDict)





# #creating a hash for a password that has been manually inserted into the list to check if lookup works
# poisonedHash = generateSHA1Hash("abdullah".encode("utf-8"))

# print("BEGIN hashDictionary lookup")
# print(isExistHashValue(poisonedHash, hashDictionary))
# print("END hashDictionary lookup")