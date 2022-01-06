import base64
import bcrypt
import hashlib
import datetime
from dateutil.parser import parse

# Role Permissions

def role_permission_list(role):
    """
    Prints out all the permissions that a role has
    """
    if role == 'patient':
        print('You have the following permissions as a Patient:')
        print('Patient can read their own profile')
        print('Patient can read their own history')
        print('Patient can read their own physician contact details')
    if role == 'administrator':
        print('You have the following permissions as an Administrator:')
        print('Administrator can read all patient profiles')
        print('Administrator can write to all patient profiles')
    if role == 'physician':
        print('You have the following permissions as a Physician:')
        print('Physician can read all patient profiles')
        print('Physician can read all medical images')
        print('Physician can write new diagnosis inside all patient histories')
        print('Radiologist can write new treatment inside all patient histories')
    if role == 'radiologist':
        print('You have the following permissions as a Radiologist:')
        print('Radiologist can read all patient profiles')
        print('Radiologist can read all medical images')
        print('Physician can write new diagnosis inside all patient histories')
    if role == 'nurse':
        print('You have the following permissions as a Nurse:')
        print('Nurse can read all patient profiles')
        print('Nurse can read all medical images')
    if role == 'technical support':
        print('You have the following permissions as a Technical Support:')
        print('Technical Support can execute all imaging units diagnostic tests')
        print('Technical Support can read all imaging units tests results')

def time_in_range(start_time, end_time, current_time):
    """
    Return true if current time is in range of
    start time and end time
    """
    return start_time <= current_time <= end_time

def authenticate_role(role_name, object, activity):
    """
    Authenticates the user by checking their roles.
    Returns True if the user's role has permission to perform
    the activity, and False otherwise.
    """

    # For an administrator, if the time is not between
    # 9:00 and 5:00, the administrator cannot
    # interact with the system
    if role_name == 'administrator':
        start_time = datetime.time(9, 0, 0)
        end_time = datetime.time(17, 0, 0)
        current_time = datetime.datetime.now().time()
        if time_in_range(start_time, end_time, current_time) == False:
            return False
        
    if role_name == 'patient':
        if activity == 'read':
            if object == 'own_profile':
                return True
            if object == 'own_history':
                return True
            if object == 'own_physician_contact_detail':
                return True

    if role_name == 'administrator':
        if object == 'patient_profile':
            if activity == 'read':
                return True
            if activity == 'write':
                return True

    if role_name == 'physician':
        if object == 'patient_profile':
            if activity == 'read':
                return True
        if object == 'patient_history':
            if activity == 'read':
                return True
        if object == 'medical_images':
            if activity == 'read':
                return True
        if object == 'diagnosis_inside_patient_history':
            if activity == 'write':
                return True
        if object == 'treatment_inside_patient_history':
            if activity == 'write':
                return True

    if role_name == 'radiologist':
        if object == 'patient_profile':
            if activity == 'read':
                return True
        if object == 'patient_history':
            if activity == 'read':
                return True
        if object == 'medical_images':
            if activity == 'read':
                return True
        if object == 'diagnosis_inside_patient_history':
            if activity == 'write':
                return True

    if role_name == 'nurse':
        if object == 'patient_profile':
            if activity == 'read':
                return True
        if object == 'patient_history':
            if activity == 'read':
                return True
        if object == 'medical_images':
            if activity == 'read':
                return True

    if role_name == 'technical support':
        if object == 'imaging_units_diagnostic_tests':
            if activity == 'execute':
                return True
        if object == 'imaging_units_tests_results':
            if activity == 'read':
                return True
    
    # Returns false if the user does not have permission
    return False

# Password Input

class Password:
    userID = ''
    role = ''
    salt = ''
    hashcode = ''

    def __init__(self, userID, role, salt, hashcode):
        self.userID = userID
        self.role = role
        self.salt = salt
        self.hashcode = hashcode
    
    def get_userID(self):
        return self.userID

    def get_role(self):
        return self.role

    def get_salt(self):
        return self.salt

    def get_hashcode(self):
        return self.hashcode

def retrieve_from_passwd_file():
    """
    Retrieves the password information from the file line by line
    and stores each of them in a list of Password objects
    """
    passwords = []

    for line in open("passwd.txt","r").readlines(): # Read the lines
        passwords_info = line.split() # Split on the space, and store the results in a list of two strings

        userID = passwords_info[0]
        role = passwords_info[1]
        salt = passwords_info[2]
        hashcode = passwords_info[3]
        passwords.append(Password(userID, role, salt, hashcode))

    return passwords

def store_password(Password):
    """
    Stores a Password object in string form in a single line and append it into the password text file
    """
    with open('passwd.txt', 'a') as file:
        # Write the username, salt, and hashcode to the file, and then add a new line
        file.write(Password.get_userID() + ' ' + Password.get_role() + ' ' + Password.get_salt() + ' ' + Password.get_hashcode() + '\n')

def add_user(userID, role, password):
    """
    Adds a new user to the passwds.txt text file

    Hashes a password using the bcrypt gensalt algorithm for generating salt
    and then hashes the password using the hashlib pbkdf2_hmac algorithm
    and adds the userID, the role, the salt, and the hashcode to the passwords dictionary
    """
    
    # Generate a random salt using bcrypt gensalt function for 16 rounds
    salt = bcrypt.gensalt(rounds=16)

    # Create password hash using the hashlib.pbkdf2_hmac function with the salt for 150,500 iterations
    # also encode the password to utf-8 format as the hashlib function requires Byte strings
    hashcode = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 150500)

    # Store the password in the passwds.txt text file
    # encodes the salt and hashcode in base64 to decode it using the utf-8 codec to get back a string from the bytes
    store_password(Password(userID, role, base64.b64encode(salt).decode('utf-8'), base64.b64encode(hashcode).decode('utf-8')))

def authenticate(userID, password):
    """
    Authenticates the user against the passwds.txt passwords file
    by first checking if the userID exists
    and then comparing the hashed password

    Returns True if the userID and password match, and False otherwise
    """
    passwords = retrieve_from_passwd_file()
    for i in range(0,len(passwords)):
        if userID == passwords[i].get_userID():
            # Encode the salt from the passwds.txt passwords file to bytes form
            salt = base64.b64decode(passwords[i].get_salt().encode('utf-8'))

            # Encode the hashcode from the passwds.txt passwords file to bytes form
            hashcode = base64.b64decode(passwords[i].get_hashcode().encode('utf-8'))

            # Use utf-8 codec to encode the inputted password to bytes
            # Use the pbkdf2_hmac function to hash the inputted password using the salt stored in the passwds.txt file
            entered_hashcode = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 150500)
            
            # Use b64encode and utf-8 codec to decode the hashed password to string form and compare the hashed password
            # If the hashcodes match, authentication is successful
            if entered_hashcode == hashcode:
                return True
            else:
                return False

# Password Checker

def check_userID_duplicate(userID):
    """
    Checks if the userID is already in the passwds.txt text file.
    Returns True if the userID is already in the passwds.txt text file,
    and False otherwise.
    """
    passwords = retrieve_from_passwd_file()
    for i in range(0,len(passwords)):
        if userID == passwords[i].get_userID():
            return True
    return False

def check_valid_role(role):
    """
    Checks if the role is valid, return true if it is, and false otherwise.
    """
    if role == 'patient' or role == 'administrator' or role == 'physician' or role == 'radiologist' or role == 'nurse' or role == 'technical support':
        return True
    else:
        return False

def check_weak_password(password):
    '''
    Checks if the password is in list of weak passwords
    '''
    # read the lines for weak passwords
    for line in open("weak_passwds.txt","r").readlines():
        # if there is a match, return True
        if password == line:
            return True
    return False

def is_date(string):
    """
    Returns whether the string can be interpreted as a date from
    using Python's dateutil.parser library. If it can parse, it will
    return true, and false otherwise.
    """
    try: 
        parse(string, fuzzy=False)
        return True

    except ValueError:
        return False

def is_license_plate(string):
    """
    Retruns true when the string is in Ontario license plate
    with example format such as ABCD-012, with 4 letters, followed
    by a hyphen, and 3 numbers.
    """
    if string[0].isalpha():
        if string[1].isalpha():
            if string[2].isalpha():
                if string[3].isalpha():
                    if string[4] == '-':
                        if string[5].isdigit():
                            if string[6].isdigit():
                                if string[7].isdigit():
                                    return True
    return False
                        
def password_checker(password):
    """
    Checks if the password is valid
    return true if it is and false otherwise
    """
    if len(password) < 8:
        return False
    if len(password) > 12:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in '!@#$%?*' for char in password):
        return False
    if check_weak_password(password):
        return False
    if is_date(password):
        return False
    if is_license_plate(password):
        return False
    else:
        return True

def user_enrolment_interface():
    """
    User interface for the user enrolment system
    """
    print('Welcome to the MedView Imaging user enrolment system')
    print('----------------------------------------------------')
    while True:
        print('Please choose a userID:')
        userID = input('Enter a userID: ')
        if check_userID_duplicate(userID):
            print('UserID already exists')
            print('Please try again')
        else:
            print('---------------------')
            print('Please choose a role:')
            print('Please use all lowercase')
            print('---------------------')
            print('Available Options:')
            print('patient')
            print('administrator')
            print('physician')
            print('radiologist')
            print('nurse')
            print('technical support')
            role = input('Enter a role: ')
            if check_valid_role(role):
                print('-------------------------')
                print('Please choose a password:')
                print('-------------------------')
                print('passwords must have ')
                print('1. 8-12 characters')
                print('2. at least one uppercase letter')
                print('3. at least one lowercase letter')
                print('4. at least one number')
                print('5. at least one special character')
                print(' from using: !, @, #, $, %, ?, ∗')
                print('6. not a weak password')
                password = input('Enter a password: ')
                if password_checker(password):
                    add_user(userID, role, password)
                    print('User added successfully')
                    break
                else:
                    print('Password is invalid')
                    print('Please try again')
            else:
                print('Role is invalid')
                print('Please try again')

# User Interface

def retrieve_role(userID):
    """
    Returns the role of the userID
    """
    passwords = retrieve_from_passwd_file()
    for i in range(0,len(passwords)):
        if userID == passwords[i].get_userID():
            return passwords[i].get_role()

def login_interface():
    """
    User interface for the login system
    """
    print('Welcome to the MedView Imaging login system')
    print('-----------------------------------------')
    while True:
        print('Please enter your userID:')
        userID = input('Enter a userID: ')
        print('Please enter your password:')
        password = input('Enter a password: ')
        if authenticate(userID, password):
            print('Login successful')
            print('Welcome ' + userID)
            print('You are logged in as ' + retrieve_role(userID))
            print('The current time is ' + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            role_permission_list(retrieve_role(userID))
            user_action_interface(userID)
            break
        else:
            print('Login failed')
            print('Please try again')

def user_action_interface(userID):
    '''
    User interface for the user action system for MedView Imaging
    Takes the userID, and prints out the actions that the user can do
    
    And also use authentication with the authenticate_role function
    to check if the user has the permission to do the action
    '''
    while True:
        print('-----------------------------------------------------')
        print('MedView Imaging System')
        print('Please choose an action by selecting the number only:')
        print('1. Read your own patient profile')
        print('2. Read your own patient history')
        print('3. Read your own physician contact details')
        print('4. Read all patient profiles')
        print('5. Write to all patient profiles')
        print('6. Read all medical images')
        print('7. Write new diagnosis inside all patient histories')
        print('8. Write new treatment inside all patient histories')
        print('9. Execute all imaging units diagnostic tests')
        print('10. Read all imaging units tests results')
        print('11. Logout')
        user_role = retrieve_role(userID)
        action = input('Enter an action: ')
        print('------------------Permission Result------------------')
        if action == '1':
            if authenticate_role(user_role, 'own_profile', 'read'):
                print('You can read your own patient profile')
            else:
                print('You cannot read your own patient profile')
        elif action == '2':
            if authenticate_role(user_role, 'own_history', 'read'):
                print('You can read your own patient history')
            else:
                print('You cannot read your own patient history')
        elif action == '3':
            if authenticate_role(user_role, 'own_physician_contact_detail', 'read'):
                print('You can read your own physician contact details')
            else:
                print('You cannot read your own physician contact details')
        elif action == '4':
            if authenticate_role(user_role, 'patient_profile', 'read'):
                print('You can read all patient profiles')
            else:
                print('You cannot read all patient profiles')
        elif action == '5':
            if authenticate_role(user_role, 'patient_profile', 'write'):
                print('You can write to all patient profiles')
            else:
                print('You cannot write to all patient profiles')
        elif action == '6':
            if authenticate_role(user_role, 'medical_images', 'read'):
                print('You can read all medical images')
            else:
                print('You cannot read all medical images')
        elif action == '7':
            if authenticate_role(user_role, 'diagnosis_inside_patient_history', 'write'):
                print('You can write new diagnosis inside all patient histories')
            else:
                print('You cannot write new diagnosis inside all patient histories')
        elif action == '8':
            if authenticate_role(user_role, 'treatment_inside_patient_history', 'write'):
                print('You can write new treatment inside all patient histories')
            else:
                print('You cannot write new treatment inside all patient histories')
        elif action == '9':
            if authenticate_role(user_role, 'imaging_unit_test', 'execute'):
                print('You can execute all imaging units diagnostic tests')
            else:
                print('You cannot execute all imaging units diagnostic tests')
        elif action == '10':
            if authenticate_role(user_role, 'imaging_unit_test_result', 'read'):
                print('You can read all imaging units tests results')
            else:
                print('You cannot read all imaging units tests results')
        elif action == '11':
            print('Thank you for using MedView User Interface, Goodbye')
            print('-----------------------------------------------------')
            break
        else:
            print('Invalid action')

def medview_imaging_interface_demo():
    """
    Demo interface used to demo the program
    Can be used to access the MedView user enroller system
    and the login system
    """
    while True:
        print('-----------------------------------------------------')
        print('MedView Imaging System Demo')
        print('Please choose an action by selecting the number only:')
        print('1. MedView user enrolement system')
        print('2. MedView user login system')
        print('3. Quit Demo')
        action = input('Enter an action: ')
        if action == '1':
            user_enrolment_interface()
        elif action == '2':
            login_interface()
        elif action == '3':
            print('Thank you for using MedView Imaging System Demo, Goodbye')
            print('-----------------------------------------------------')
            break

medview_imaging_interface_demo()
