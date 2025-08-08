# The socket module allows low-level network communication.
# In this script, we use it to check if the computer can connect to the internet
# by trying to establish a connection to a known external server (like Google's DNS).

import socket

class InternetChecker:
    choice = 0
    def __init__(self):
        pass

    # This method allows
    def check_basic_connection(self, website):
        """
        Checks internet connectivity by testing common network ports on a given website or IP.

        If no website is provided, defaults to 8.8.8.8 (google.com).
        Prints which ports successfully connected to confirm internet access.
        """
        print("Running basic internet connectivity test...")
        if website == "": website = "8.8.8.8"
        ports = [53, 443, 80, 22, 21, 25, 110, 143, 3389]
        successfull_port = []
        print ("Checking available port connections...")
        for port in ports:
            try :
                successfull_port.append(port)
                n = socket.create_connection(("8.8.8.8", port), timeout=3)
            except :
                successfull_port.pop()
        if (len(successfull_port) > 0):
            print(f"Internet connection is active. Successful connection to the following ports: {successfull_port}")
        else:
            print("No internet connection detected.")

    def show_menu(self):
        """
        Displays a menu for internet connectivity checks.

        - Offers two options: check connection or return to main menu.
        - If the user selects option 1, they're asked to enter a website (or leave blank to use 8.8.8.8).
        - Passes the website to the check_basic_connection() method to test connectivity.
        """
        print("\n=== Internet Connectivity Menu ===")
        print("1. Check basic internet connection")
        print("2. Return to main menu")
        choice = input("Enter your choice (1–2): ")
        if choice == "1":
            website = input ("\nWhat website do you want to check? (leave blank to default to google.com): ")
            self.check_basic_connection(website)


