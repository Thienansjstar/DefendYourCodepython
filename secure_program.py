# Team Name: team 11
# Team Members: Eva, Thienan, ibadut 

import logging
import re

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os

logging.basicConfig(
    filename='error.log', 
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_valid_name(prompt_type):
    while True:
        print(f"\n--- {prompt_type} Name ---")
        print("Rules: Max 50 characters. Only letters, spaces, and hyphens allowed.")
        
        name = input(f"Enter your {prompt_type} name: ").strip()
        
        if len(name) == 0 or len(name) > 50:
            error_msg = f"Invalid length for {prompt_type} name: '{name}'"
            print("Error: Name must be between 1 and 50 characters.")
            logging.error(error_msg)
            continue 
            
        if not re.match(r"^[A-Za-z\s\-]+$", name):
            error_msg = f"Invalid characters in {prompt_type} name: '{name}'"
            print("Error: Name can only contain letters, spaces, and hyphens.")
            logging.error(error_msg)
            continue
            
        return name
    
def get_valid_integer(prompt_num):

    MIN_INT = -2147483648
    MAX_INT = 2147483647
    
    while True:
        print(f"\n--- {prompt_num.capitalize()} Integer ---")
        print(f"Rules: Must be a whole number between {MIN_INT:,} and {MAX_INT:,}.")
        
        user_input = input(f"Enter your {prompt_num} integer: ").strip()
        
        try:
            number = int(user_input)
            
            if number < MIN_INT or number > MAX_INT:
                error_msg = f"Integer out of bounds: {number}"
                print("Error: Number is too large or too small.")
                logging.error(error_msg)
                continue
                
            return number
            
        except ValueError:
            error_msg = f"Non-integer input provided: '{user_input}'"
            print("Error: You must enter a valid whole number.")
            logging.error(error_msg)


def get_valid_input_file():

    while True:
        print("Rules: Must be a .txt file in the current directory. No slashes or special characters allowed.")
        filename = input("Enter the name of the input file: ").strip()
        
        if not re.match(r"^[a-zA-Z0-9_-]+\.txt$", filename):
            error_msg = f"Invalid input file format/characters: '{filename}'"
            print("Error: File name must only contain letters, numbers, dashes, or underscores, and end with .txt.")
            logging.error(error_msg)
            continue

        if not os.path.isfile(filename):
            error_msg = f"Input file not found: '{filename}'"
            print(f"Error: The file '{filename}' does not exist in the current directory.")
            logging.error(error_msg)
            continue
            
        return filename
    
def get_valid_output_file(input_filename):
 
    while True:
        print("Rules:Output file Must be a .txt file. Cannot be the same as the input file or 'error.log'.")
        
        filename = input("Enter the name of the output file: ").strip()
        
        if not re.match(r"^[a-zA-Z0-9_-]+\.txt$", filename):
            error_msg = f"Invalid output file format: '{filename}'"
            print("Error: File name must only contain letters, numbers, dashes, or underscores, and end with .txt.")
            logging.error(error_msg)
            continue
            
        # Prevent overwriting the input file
        if filename == input_filename:
            error_msg = "Attempted to use input file as output file."
            print("Error: Output file cannot have the same name as the input file.")
            logging.error(error_msg)
            continue
            
        #Prevent overwriting the error log
        if filename == "error.log":
            error_msg = "Attempted to overwrite error.log."
            print("Error: You cannot name your output file 'error.log'.")
            logging.error(error_msg)
            continue
            
        return filename


def setup_password():

    ph = PasswordHasher() 
    
    while True:
        print("Rules: Password must be at least 15 characters long Must include uppercase, lowercase, digit, and symbol.")
        
        password = input("Create a secure password: ")
        
        if not re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:'\",.<>/?\\|`~]).{15,}$", password):
            error_msg = "User attempted to create an insecure password."
            print("Error: Password does not meet complexity requirements.")
            logging.error(error_msg)
            continue

        hashed_password = ph.hash(password)
        
        try:
            with open("temp_hash.txt", "w") as file:
                file.write(hashed_password)
            print("Password successfully secured and stored.")
            break 
            
        except IOError as e:
            error_msg = f"Failed to write password to file: {e}"
            print("System Error: Could not save password.")
            logging.error(error_msg)
            continue

def verify_password():
    """
    Reads the stored hash from the file, prompts the user to re-enter their password,
    and verifies the new entry against the stored hash and salt.
    """
    ph = PasswordHasher()
    
    try:
        with open("temp_hash.txt", "r") as file:
            saved_hash = file.read().strip()
    except FileNotFoundError:
        print("System Error: Password file not found. Cannot verify.")
        logging.error("Attempted to verify password, but temp_hash.txt is missing.")
        return False

    while True:
        attempt = input("Please re-enter your password to verify: ")
        
        try:
            ph.verify(saved_hash, attempt)
            print("Success! Password verified.")
            break
            
        except VerifyMismatchError:
            error_msg = "Failed password verification attempt."
            print("Error: Passwords do not match. Please try again.")
            logging.error(error_msg)
            continue

def calculate_safely(num1, num2):
    """
    writes the user's name
    writes the result of adding the two integer values (no overflow should occur)
    writes the result of multiplying the two integer values (no overflow should occur),
    writes the contents of the input file
    """
    MIN_INT = -2147483648
    MAX_INT = 2147483647
    
    # Check Addition
    sum_val = num1 + num2
    if sum_val < MIN_INT or sum_val > MAX_INT:
        add_res = "Error: Overflow"
        logging.error(f"Integer overflow during addition: {num1} + {num2}")
    else:
        add_res = str(sum_val)
        
    # Check Multiplication
    prod_val = num1 * num2
    if prod_val < MIN_INT or prod_val > MAX_INT:
        mult_res = "Error: Overflow"
        logging.error(f"Integer overflow during multiplication: {num1} * {num2}")
    else:
        mult_res = str(prod_val)
        
    return add_res, mult_res

def write_final_output(out_filename, in_filename, first_name, last_name, num1, num2, add_res, mult_res):

    try:
        with open(in_filename, 'r') as f_in:
            input_contents = f_in.read()
    except IOError as e:
        error_msg = f"Failed to read input file '{in_filename}': {e}"
        logging.error(error_msg)
        input_contents = "[Error: Could not read input file contents at execution time.]"

    try:
        with open(out_filename, 'w') as f_out:
            f_out.write("OUTPUT\n")
            f_out.write(f"First Name: {first_name}\n")
            f_out.write(f"Last Name: {last_name}\n")
            f_out.write(f"First Integer: {num1}\n")
            f_out.write(f"Second Integer: {num2}\n")
            f_out.write(f"Sum: {add_res}\n")
            f_out.write(f"Product: {mult_res}\n")
            f_out.write(f"\nInput File Name: {in_filename}\n")
            f_out.write("Input File Contents\n")
 
            f_out.write(input_contents + "\n")
            
        print(f"\nSUCCESS All data has been securely written to '{out_filename}'.")
        
    except IOError as e:
        error_msg = f"Failed to write to output file '{out_filename}': {e}"
        print("\nSystem Error: Could not write to the output file. Please check permissions.")
        logging.error(error_msg)
        
if __name__ == "__main__":
    print("Welcome to the Secure Data Entry Program.")
    
    first_name = get_valid_name("First")
    last_name = get_valid_name("Last")
    num1 = get_valid_integer("first")
    num2 = get_valid_integer("second")
    in_file = get_valid_input_file()
    out_file = get_valid_output_file(in_file)
    setup_password()
    verify_password()
    sum_result, product_result = calculate_safely(num1, num2)
    write_final_output(out_file, in_file, first_name, last_name, num1, num2, sum_result, product_result)
    
    print("Program completed successfully")