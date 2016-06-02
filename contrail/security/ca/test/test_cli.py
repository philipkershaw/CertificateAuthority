'''
Created on Jun 1, 2016

@author: philipkershaw
'''
import unittest

from contrail.security.ca.utils import gen_ca_cert


class Test(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass


    def testName(self):
        gen_ca -c ca2.crt -k ca2.key -s 'O=Org,OU=Org unit,CN=Common name'


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()