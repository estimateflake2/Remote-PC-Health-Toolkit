import shutil
import os
import string

class DiskUsageTool:
    def __init__(self):
        pass

    def get_all_drives(self):
        drives = []
        if os.name == 'nt':  # Windows
            # Check all possible drive letters
            for letter in string.ascii_uppercase:
                drive = f"{letter}:/"
                if os.path.exists(drive):
                    drives.append(drive)
        else:  # Linux/macOS
            # Typically mount points under / or /mnt or /media
            drives.append("/")
            mnt_points = ["/mnt", "/media"]
            for path in mnt_points:
                if os.path.exists(path):
                    for d in os.listdir(path):
                        drives.append(os.path.join(path, d))
        return drives

    def check_disk_usage(self, path):
        total, used, free = shutil.disk_usage(path)
        # Convert bytes to gigabytes (GB)
        gb_total = total / (1024 ** 3)
        gb_used = used / (1024 ** 3)
        gb_free = free / (1024 ** 3)
        percent_used = (used / total) * 100

        return {
            "total_gb": round(gb_total, 2),
            "used_gb": round(gb_used, 2),
            "free_gb": round(gb_free, 2),
            "percent_used": round(percent_used, 2)
        }

    def get_aval_drives(self):
        disks = self.get_all_drives()
        disk = ''
        if len(disks) == 1:
            disk = disks[0]
        elif len(disks) > 1:
            for i, d in enumerate(disks):
                if i == 0:
                    disk = d
                else:
                    disk += ', ' + d
        return disk

    def show_menu(self):
        exit_menu = False
        while not exit_menu:
            print("\n=== Disk Usage Menu ===")
            print(f"Drives Found: ({self.get_aval_drives()})")
            print("1. Check drive sizes")
            print("2. Return to main menu")
            choice = input("Enter your choice (1–2): ")
            if choice == "1":
                # call check_disk_usage for each drive
                for d in self.get_all_drives():
                    try:
                        stats = self.check_disk_usage(d)
                        print(f"{d} - Total: {stats['total_gb']} GB | "
                              f"Used: {stats['used_gb']} GB | "
                              f"Free: {stats['free_gb']} GB | "
                              f"Used %: {stats['percent_used']}%")
                    except PermissionError:
                        print(f"Permission denied for {d}")
            elif choice == "2":
                exit_menu = True
            else:
                print("Invalid choice. Please enter a number from 1 to 2.")


# Run directly
if __name__ == "__main__":
    tool = DiskUsageTool()
    tool.show_menu()
# import shutil
# import os
# import string
#
# def get_all_drives():
#     drives = []
#     if os.name == 'nt':  # Windows
#         # Check all possible drive letters
#         for letter in string.ascii_uppercase:
#             drive = f"{letter}:/"
#             if os.path.exists(drive):
#                 drives.append(drive)
#     else:  # Linux/macOS
#         # Typically mount points under / or /mnt or /media
#         # You can refine this depending on your system
#         drives.append("/")
#         mnt_points = ["/mnt", "/media"]
#         for path in mnt_points:
#             if os.path.exists(path):
#                 for d in os.listdir(path):
#                     drives.append(os.path.join(path, d))
#     return drives
#
# def check_disk_usage(path):
#     total, used, free = shutil.disk_usage(path)
#     # Convert bytes to gigabytes (GB)
#     gb_total = total / (1024 ** 3)
#     gb_used = used / (1024 ** 3)
#     gb_free = free / (1024 ** 3)
#     percent_used = (used / total) * 100
#
#     return {
#         "total_gb": round(gb_total, 2),
#         "used_gb": round(gb_used, 2),
#         "free_gb": round(gb_free, 2),
#         "percent_used": round(percent_used, 2)
#     }
# def get_aval_drives():
#     disks = get_all_drives()
#     disk = ''
#     if len(disks) == 1:
#         disk = disks[0]
#     elif len(disks) >1:
#         for i, d in enumerate(disks):
#             if i == 0:
#                 disk = d
#             else:
#                 disk += ', '+d
#     return disk
#
# def show_menu():
#     exit_menu = False
#     while not exit_menu:
#         print("\n=== Disk Usage Menu ===")
#         print(f"Drives Found: ({get_aval_drives()})")
#         print("1. Check drive sizes")
#         print("2. Return to main menu")
#         choice = input("Enter your choice (1–2): ")
#         if choice == "1":
#             check_disk_usage(get_all_drives())
#         elif choice == "2":
#             exit_menu = True
#         else:
#             print("Invalid choice. Please enter a number from 1 to 2.")
#
# show_menu()