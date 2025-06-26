#!/usr/bin/env python3
"""
Simple test runner for HBC96 overflow functionality
Usage: poetry run python run_tests.py
"""

import unittest
import sys
sys.path.insert(0, '.')

from hbctool.hbc.hbc96 import HBC96
from hbctool.util import *

class TestHBC96OverflowSuite(unittest.TestCase):
    """Comprehensive test suite for HBC96 overflow handling"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.hbc = HBC96()
        self.mock_obj = {
            'header': {'functionCount': 1, 'stringCount': 1, 'arrayBufferSize': 0, 'objKeyBufferSize': 0, 'objValueBufferSize': 0},
            'functionHeaders': [{
                'offset': 0x1000, 'paramCount': 1, 'frameSize': 2, 'environmentSize': 0,
                'bytecodeSizeInBytes': 100, 'functionName': 0, 'infoOffset': 0,
                'highestReadCacheIndex': 0, 'highestWriteCacheIndex': 0, 'flags': 0
            }],
            'stringTableEntries': [{'isUTF16': 0, 'offset': 0, 'length': 4}],
            'stringTableOverflowEntries': [],
            'stringStorage': list(b'test'),
            'instOffset': 0x1000,
            'inst': [0] * 50000,
            'arrayBuffer': [], 'objKeyBuffer': [], 'objValueBuffer': []
        }
        self.hbc.setObj(self.mock_obj)

    def test_normal_function_modification(self):
        """Test normal function modification without overflow"""
        functionName, paramCount, registerCount, symbolCount, insts, funcHeader = self.hbc.getFunction(0)
        
        # Small bytecode
        small_bytecode = [0x01, 0x02, 0x03]
        new_func = (functionName, paramCount + 1, registerCount + 1, symbolCount, small_bytecode, funcHeader)
        self.hbc.setFunction(0, new_func, disasm=False)
        
        header = self.hbc.getObj()['functionHeaders'][0]
        self.assertEqual(header['bytecodeSizeInBytes'], 3)
        self.assertEqual(header['flags'] & (1 << 5), 0)
        self.assertNotIn('small', header)
        print('✅ Normal function modification test passed')

    def test_15_bit_boundary_exact(self):
        """Test exact 15-bit boundary (32767 bytes) - should NOT overflow"""
        functionName, paramCount, registerCount, symbolCount, insts, funcHeader = self.hbc.getFunction(0)
        
        boundary_bytecode = [0x77] * 32767
        new_func = (functionName, paramCount, registerCount, symbolCount, boundary_bytecode, funcHeader)
        self.hbc.setFunction(0, new_func, disasm=False)
        
        header = self.hbc.getObj()['functionHeaders'][0]
        self.assertEqual(header['bytecodeSizeInBytes'], 32767)
        self.assertEqual(header['flags'] & (1 << 5), 0)  # Should not overflow
        self.assertNotIn('small', header)
        print('✅ 15-bit boundary test passed')

    def test_15_bit_boundary_over(self):
        """Test one byte over 15-bit boundary (32768 bytes) - should overflow"""
        functionName, paramCount, registerCount, symbolCount, insts, funcHeader = self.hbc.getFunction(0)
        
        over_boundary_bytecode = [0x88] * 32768
        new_func = (functionName, paramCount, registerCount, symbolCount, over_boundary_bytecode, funcHeader)
        self.hbc.setFunction(0, new_func, disasm=False)
        
        header = self.hbc.getObj()['functionHeaders'][0]
        self.assertEqual(header['bytecodeSizeInBytes'], 32768)
        self.assertNotEqual(header['flags'] & (1 << 5), 0)  # Should overflow
        self.assertIn('small', header)
        print('✅ Over 15-bit boundary test passed')

    def test_large_bytecode_overflow(self):
        """Test large bytecode overflow mechanism"""
        functionName, paramCount, registerCount, symbolCount, insts, funcHeader = self.hbc.getFunction(0)
        
        large_bytecode = [0xFF] * 50000
        new_func = (functionName, paramCount, registerCount, symbolCount, large_bytecode, funcHeader)
        self.hbc.setFunction(0, new_func, disasm=False)
        
        header = self.hbc.getObj()['functionHeaders'][0]
        self.assertEqual(header['bytecodeSizeInBytes'], 50000)
        self.assertNotEqual(header['flags'] & (1 << 5), 0)
        self.assertIn('small', header)
        print('✅ Large bytecode overflow test passed')

    def test_overflow_flag_clearing(self):
        """Test clearing overflow flag when function size reduces"""
        functionName, paramCount, registerCount, symbolCount, insts, funcHeader = self.hbc.getFunction(0)
        
        # First trigger overflow
        large_bytecode = [0xFF] * 40000
        new_func = (functionName, paramCount, registerCount, symbolCount, large_bytecode, funcHeader)
        self.hbc.setFunction(0, new_func, disasm=False)
        
        header = self.hbc.getObj()['functionHeaders'][0]
        self.assertNotEqual(header['flags'] & (1 << 5), 0)
        self.assertIn('small', header)
        
        # Now set smaller bytecode
        small_bytecode = [0x11] * 100
        new_func = (functionName, paramCount, registerCount, symbolCount, small_bytecode, funcHeader)
        self.hbc.setFunction(0, new_func, disasm=False)
        
        header = self.hbc.getObj()['functionHeaders'][0]
        self.assertEqual(header['flags'] & (1 << 5), 0)
        self.assertNotIn('small', header)
        self.assertEqual(header['bytecodeSizeInBytes'], 100)
        print('✅ Overflow flag clearing test passed')

if __name__ == '__main__':
    print('🔧 Running HBC96 Overflow Test Suite...')
    print('=' * 50)
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestHBC96OverflowSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print('=' * 50)
    print(f'Tests run: {result.testsRun}')
    print(f'Failures: {len(result.failures)}')
    print(f'Errors: {len(result.errors)}')
    
    if result.wasSuccessful():
        print('🎉 All HBC96 overflow tests passed!')
        sys.exit(0)
    else:
        print('❌ Some tests failed')
        sys.exit(1) 