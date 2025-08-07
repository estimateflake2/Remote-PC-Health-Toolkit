import sys

def show_menu():
    print("\n=== Remote PC Health Toolkit ===")
    print("1. Check Internet Connection")
    print("2. Check Disk Usage")
    print("3. Check System Uptime")
    print("4. Run Speed Test")
    print("5. Exit")

def main():
    while True:
        show_menu()
        choice = input("Enter your choice (1–5): ")

        if choice == '1':
            print("Running internet connectivity check... (Coming soon!)")
        elif choice == '2':
            print("Checking disk usage... (Coming soon!)")
        elif choice == '3':
            print("Checking system uptime... (Coming soon!)")
        elif choice == '4':
            print("Running speed test... (Coming soon!)")
        elif choice == '5':
            print("Exiting... Stay safe!")
            sys.exit()
        else:
            print("Invalid choice. Please enter a number from 1 to 5.")

if __name__ == "__main__":
    main()
