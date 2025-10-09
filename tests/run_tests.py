#!/usr/bin/env python3
"""
Test runner for Project Revelare
"""

import unittest
import sys
import os
import argparse
from io import StringIO

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_tests(test_type='all', verbose=False):
    """Run tests based on type"""
    
    test_dir = os.path.dirname(__file__)
    
    # Set up test loader
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    if test_type == 'all':
        # Discover all tests
        suite = loader.discover(test_dir, pattern='test_*.py')
    elif test_type == 'unit':
        # Load specific unit test files
        test_files = ['test_extractor.py', 'test_security.py', 'test_data_enhancer.py']
        for test_file in test_files:
            test_path = os.path.join(test_dir, test_file)
            if os.path.exists(test_path):
                # Load tests from the file
                suite.addTests(loader.loadTestsFromName(test_file[:-3], test_dir))
    elif test_type == 'integration':
        # Load integration tests
        test_path = os.path.join(test_dir, 'test_integration.py')
        if os.path.exists(test_path):
            suite.addTests(loader.loadTestsFromName('test_integration', test_dir))
    else:
        print(f"Unknown test type: {test_type}")
        return False
    
    # Set up test runner
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stdout)
    
    # Run tests
    print(f"Running {test_type} tests...")
    print("=" * 50)
    
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    if result.testsRun > 0:
        print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    else:
        print("Success rate: N/A (no tests found)")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    return result.wasSuccessful()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Run Project Revelare tests')
    parser.add_argument('--type', choices=['all', 'unit', 'integration'], 
                       default='all', help='Type of tests to run')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose output')
    
    args = parser.parse_args()
    
    success = run_tests(args.type, args.verbose)
    
    if success:
        print("\n[SUCCESS] All tests passed!")
        sys.exit(0)
    else:
        print("\n[FAILED] Some tests failed!")
        sys.exit(1)

if __name__ == '__main__':
    main()
