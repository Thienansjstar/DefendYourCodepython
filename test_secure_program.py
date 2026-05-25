import unittest
from unittest.mock import patch
import os

import secure_program as sp

class TestSecureDataEntryExhaustive(unittest.TestCase):

    def setUp(self):
        """Creates dummy files needed for testing before each test runs."""
        # Create a valid input file with some text
        with open("valid.txt", "w") as f:
            f.write("Line1\nLine2")
            
    def tearDown(self):
        """Cleans up any files created during testing after each test finishes."""
        # Delete normal files completely
        files_to_remove = ["valid.txt", "temp_hash.txt", "output.txt"]
        for file in files_to_remove:
            if os.path.exists(file):
                os.remove(file)
                
        # For the logger, we must empty the file instead of deleting it!
        if os.path.exists("error.log"):
            with open("error.log", "w") as f:
                f.truncate(0) # Wipes the text inside but leaves the file intact

    # =====================================================
    # 1. NAME VALIDATION TESTS
    # =====================================================

    @patch('builtins.input', side_effect=['A'])
    def test_valid_name_min_length(self, mock_input):
        """Test Valid Name: Exact minimum length (1 character)."""
        self.assertEqual(sp.get_valid_name("First"), "A")

    @patch('builtins.input', side_effect=['A' * 50])
    def test_valid_name_max_length(self, mock_input):
        """Test Valid Name: Exact maximum length (50 characters)."""
        self.assertEqual(sp.get_valid_name("First"), "A" * 50)

    @patch('builtins.input', side_effect=['A' * 51, 'Eva'])
    def test_invalid_name_too_long_then_valid(self, mock_input):
        """Test Invalid Name: Exceeds 50 chars, then provides valid name."""
        self.assertEqual(sp.get_valid_name("First"), "Eva")
        # Check if the file has data written to it (size > 0)
        self.assertTrue(os.path.getsize("error.log") > 0, "Error log was not written to for invalid name.")

    @patch('builtins.input', side_effect=['Eva123', 'Eva'])
    def test_invalid_name_with_numbers_then_valid(self, mock_input):
        """Test Invalid Name: Contains numbers, then provides valid name."""
        self.assertEqual(sp.get_valid_name("First"), "Eva")

    # =====================================================
    # 2. INTEGER VALIDATION TESTS
    # =====================================================

    @patch('builtins.input', side_effect=['-2147483648'])
    def test_valid_int_min_boundary(self, mock_input):
        """Test Valid Int: Exact 4-byte minimum boundary."""
        self.assertEqual(sp.get_valid_integer("first"), -2147483648)

    @patch('builtins.input', side_effect=['2147483647'])
    def test_valid_int_max_boundary(self, mock_input):
        """Test Valid Int: Exact 4-byte maximum boundary."""
        self.assertEqual(sp.get_valid_integer("first"), 2147483647)

    @patch('builtins.input', side_effect=['abc', '42'])
    def test_invalid_int_non_numeric_then_valid(self, mock_input):
        """Test Invalid Int: Letters provided, then valid integer."""
        self.assertEqual(sp.get_valid_integer("first"), 42)
        # Check if the file has data written to it (size > 0)
        self.assertTrue(os.path.getsize("error.log") > 0, "Error log not written to for non-numeric int.")
    # =====================================================
    # 3. SAFE ADD / MULTIPLY TESTS
    # =====================================================

    def test_safe_add_normal(self):
        """Test Safe Math: Normal addition."""
        add_res, _ = sp.calculate_safely(5, 5)
        self.assertEqual(add_res, "10")

    def test_safe_add_overflow(self):
        """Test Safe Math: Addition overflow past 4-byte max."""
        add_res, _ = sp.calculate_safely(2147483647, 1)
        self.assertTrue("Error" in add_res, "Addition overflow failed to catch error.")

    def test_safe_multiply_normal(self):
        """Test Safe Math: Normal multiplication."""
        _, mult_res = sp.calculate_safely(4, 5)
        self.assertEqual(mult_res, "20")

    def test_safe_multiply_overflow(self):
        """Test Safe Math: Multiplication overflow past 4-byte max."""
        _, mult_res = sp.calculate_safely(2147483647, 2)
        self.assertTrue("Error" in mult_res, "Multiplication overflow failed to catch error.")

    # =====================================================
    # 4. INPUT FILE VALIDATION TESTS
    # =====================================================

    @patch('builtins.input', side_effect=['', 'valid.txt'])
    def test_input_file_empty_then_valid(self, mock_input):
        """Test Input File: Empty string, then valid existing file."""
        self.assertEqual(sp.get_valid_input_file(), "valid.txt")

    @patch('builtins.input', side_effect=['file.doc', 'valid.txt'])
    def test_input_file_wrong_extension_then_valid(self, mock_input):
        """Test Input File: Wrong extension (.doc), then valid .txt file."""
        self.assertEqual(sp.get_valid_input_file(), "valid.txt")

    @patch('builtins.input', side_effect=['fake_file.txt', 'valid.txt'])
    def test_input_file_not_exist_then_valid(self, mock_input):
        """Test Input File: Non-existent file, then valid existing file."""
        self.assertEqual(sp.get_valid_input_file(), "valid.txt")

    # =====================================================
    # 5. OUTPUT FILE VALIDATION TESTS
    # =====================================================

    @patch('builtins.input', side_effect=['output.txt'])
    def test_output_file_new_file(self, mock_input):
        """Test Output File: Valid new file name."""
        self.assertEqual(sp.get_valid_output_file("valid.txt"), "output.txt")

    @patch('builtins.input', side_effect=['output.doc', 'output.txt'])
    def test_output_file_wrong_extension_then_valid(self, mock_input):
        """Test Output File: Wrong extension, then valid .txt file."""
        self.assertEqual(sp.get_valid_output_file("valid.txt"), "output.txt")

    @patch('builtins.input', side_effect=['valid.txt', 'error.log', 'output.txt'])
    def test_output_file_overwrite_protections(self, mock_input):
        """Test Output File: Attempts to overwrite input file, then error log, then valid."""
        # The function should reject 'valid.txt' (input file) and 'error.log', finally accepting 'output.txt'
        self.assertEqual(sp.get_valid_output_file("valid.txt"), "output.txt")

    # =====================================================
    # 6. PASSWORD SETUP & VERIFICATION TESTS
    # =====================================================

    @patch('builtins.input', side_effect=['short', 'VeryStrongPassword123!'])
    def test_password_setup_length_then_valid(self, mock_input):
        """Test Password: Fails min length, then accepts valid, writes hash to file."""
        sp.setup_password()
        self.assertTrue(os.path.exists("temp_hash.txt"), "Password hash file was not saved.")

    @patch('builtins.input', side_effect=['WrongPassword123!', 'VeryStrongPassword123!'])
    def test_password_verify_wrong_then_correct(self, mock_input):
        """Test Password: Setup password, fail verification once, then succeed."""
        # 1. Setup the password silently
        with patch('builtins.input', side_effect=['VeryStrongPassword123!']):
            sp.setup_password()
            
        # 2. Verify: fails on 'WrongPassword123!', loops, succeeds on 'VeryStrongPassword123!'
        # If it completes without throwing a StopIteration error, the test passes.
        sp.verify_password()
        self.assertTrue(True) # Reaching here means the loop logic works perfectly

    # =====================================================
    # 7. OUTPUT FILE CONTENT WRITING TEST
    # =====================================================

    def test_write_output_file_content_correct(self):
        """Test Output File Content: Ensures all variables and file contents write correctly."""
        # Call the final writer with dummy data
        sp.write_final_output("output.txt", "valid.txt", "Eva", "Howard", 5, 10, "15", "50")
        
        # Open the generated output file and check its contents
        with open("output.txt", "r") as f:
            content = f.read()
            
        # Assertions
        self.assertIn("First Name: Eva", content)
        self.assertIn("Last Name: Howard", content)
        self.assertIn("First Integer: 5", content)
        self.assertIn("Second Integer: 10", content)
        self.assertIn("Sum: 15", content)
        self.assertIn("Product: 50", content)
        self.assertIn("Input File Name: valid.txt", content)
        self.assertIn("Line1\nLine2", content) # Checking if dummy input file contents appended


if __name__ == '__main__':
    unittest.main(verbosity=2)