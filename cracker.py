"""
    Title: Vulnerability Scanner - Command Line tool
    Description: Cracks Linux shadow file given a dictionary file
    Usage: python cracker.py -h   #for help using the tool
"""

__author__ = 'Team Troy'
import argparse, os, sys
import crypt

def cli():
    """CLI Interface

    """
    p = argparse.ArgumentParser()
    p.add_argument("--shadow", help="shadow file path", default="/etc/shadow")
    p.add_argument("--dictionary", help="dictionary file path", default="/usr/share/dict/words")
    env  = p.parse_args()
    cracker = PasswordCracker(env.shadow, env.dictionary)
    cracker.start_cracking()


class PasswordCracker():
    """ Linux Password Brute Force Cracker.
        Iterates through a dictionary trying every word on the account
    """

    def __init__(self, shadow, dictionary):
        self._shadow = shadow
        self._dictionary = dictionary

    def start_cracking(self):
        user_info = self.parse_shadow_file(self._shadow)
        #reading each dictionary line only once
        for test_case in self.dictionary_iterator(self._dictionary):
            for user in user_info:
                if self.compare(test_case, user['pwd']):
                    print "******************************"
                    print "Match Found!"
                    print "For User: " + user["user"]
                    print "Password: " + test_case
                    print "******************************"


    def compare(self, plaintext, hash):
        return crypt.crypt(plaintext, hash) == hash

    def read_file(self,filename):
        if not os.access(filename, os.F_OK) or not os.access(filename, os.R_OK):
            raise Exception("File not found or not readable "  + filename)
        lines = []
        with open(filename) as fl:
            for line in fl:
                lines.append(line)
        return lines

    def parse_shadow_file(self,filename):
        lines = self.read_file(filename)
        parsed_lines = []
        for line in lines:
            splt = line.split(":")
            tmp = {}
            tmp["user"] = splt[0]
            tmp["pwd"] = splt[1]
            tmp["rest"] = splt[2:]
            parsed_lines.append(tmp)

    def dictionary_iterator(self,filename):
        if not os.access(filename, os.F_OK) or not os.access(filename, os.R_OK):
            raise Exception("File not found or not readable "+ filename)
        with open(filename) as fl:
            for line in fl:
                yield line


if __name__=="__main__":
    cli()
