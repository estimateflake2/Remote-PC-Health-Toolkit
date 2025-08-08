#===== System Up keep checker
#===== The purpose of this app is to check varios aspects of a running systems for a quick easy IT Support run through.

import sys
from lib.check_internet_connectivity import  InternetChecker

def show_menu():
    """
    Displays the main menu for the Remote PC Health Toolkit.

    Lists all available system check options, including:
    internet, disk, uptime, speed test, CPU, memory, and exit.
    """
    print("\n=== Remote PC Health Toolkit ===")
    print("1. Check Internet Connection")
    print("2. Check Disk Usage")
    print("3. Check System Uptime")
    print("4. Run Speed Test")
    print("5. Check my CPU Model")
    print("6. Check Memory (RAM) Model")
    print("7. Exit")

def check_internet_connection():
    """
    Creates an InternetChecker object and runs its internet menu.

    - Initializes the InternetChecker class.
    - Displays the sub-menu for internet-related tests.
    """
    check = InternetChecker().show_menu()


def main():
    """
    Runs the main loop for the Remote PC Health Toolkit.

    - Displays the main menu and prompts the user for a choice.
    - Handles each menu option based on user input.
    - Loops until the user selects option 7 to exit.
    """
    while True:
        show_menu()
        choice = input("Enter your choice (1–7): ")

        if choice == '1':
            check_internet_connection()
        elif choice == '2':
            print("\nChecking disk usage... (Coming soon!)")
        elif choice == '3':
            print("\nChecking system uptime... (Coming soon!)")
        elif choice == '4':
            print("\nRunning speed test... (Coming soon!)")
        elif choice == '5':
            print("\nCheck my CPU Model... (Coming soon!)")
        elif choice == '6':
            print("\nMemory Model... (Coming soon!)")
        elif choice == '7':
            print("Exiting... Stay safe!")
            sys.exit()
        else:
            print("Invalid choice. Please enter a number from 1 to 5.")
if __name__ == "__main__":
    main()