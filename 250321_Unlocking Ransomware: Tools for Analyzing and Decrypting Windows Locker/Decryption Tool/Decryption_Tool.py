import hashlib
import os
import shutil
import winreg
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pathlib import Path
import ctypes  # For changing desktop wallpaper

def decrypt_aes(ciphertext: bytes, password: str) -> bytes:
    password_bytes = hashlib.sha256(password.encode('utf-8')).digest()
    salt = bytes([3, 4, 2, 6, 5, 1, 7, 8])
    iterations = 1000
    key_iv = hashlib.pbkdf2_hmac('sha1', password_bytes, salt, iterations, dklen=48)
    key = key_iv[:32]
    iv = key_iv[32:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    try:
        plaintext = unpad(decrypted, AES.block_size)
    except ValueError:
        raise ValueError("Failed to remove padding (password may be different or data may be corrupted)")

    return plaintext

def remove_persistence():
    local_app_data = os.environ.get("LOCALAPPDATA")
    discord_path = os.path.join(local_app_data, "discord.exe")
    
    if os.path.exists(discord_path):
        os.remove(discord_path)
        print(f"Self-replicated '{discord_path}' file has been deleted")

    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
        winreg.DeleteValue(reg_key, "discord")
        winreg.CloseKey(reg_key)
        print("The 'discord' persistence entry has been removed from the registry.")
    except FileNotFoundError:
        print("Could not find 'discord' entry in registry.")
    except Exception as e:
        print(f"Failed to delete 'discord' entry from registry: {e}")

def restore_background():
    try:
        appdata_path = os.environ.get("APPDATA")  
        old_wallpaper_path = os.path.join(appdata_path, "fondo_antiguo.jpg")

        if os.path.exists(old_wallpaper_path):
            ctypes.windll.user32.SystemParametersInfoW(20, 0, old_wallpaper_path, 3)
            print(f"The original wallpaper was restored to '{old_wallpaper_path}'.")
        else:
            print("The original wallpaper file could not be found.")
    except Exception as e:
        print(f"Failed to restore wallpaper: {e}")

def decrypt_file(input_file: str, password: str, success_count: int, fail_count: int, failed_files: list):
    with open(input_file, "rb") as f:
        ciphertext = f.read()

    try:
        plaintext = decrypt_aes(ciphertext, password)
    except Exception as e:
        print(f"{input_file} Decryption Fail:", e)
        fail_count += 1
        failed_files.append(input_file) 
        return success_count, fail_count, failed_files


    output_file = os.path.splitext(input_file)[0]  
    
    with open(output_file, "wb") as f:
        f.write(plaintext)

    os.remove(input_file)

    print(f"{input_file} Decryption success!")
    
    success_count += 1
    return success_count, fail_count, failed_files

def decrypt_specified_folders(base_folder: str, password: str):
    success_count = 0
    fail_count = 0
    failed_files = []

    directories_to_check = [
        "Desktop",
        "Pictures",
        "Downloads",
        "Documents",
        "Music",
        "3D Objects",
        "OneDrive"
    ]
    
    for directory_name in directories_to_check:
        directory_path = os.path.join(base_folder, directory_name)
        
        if os.path.exists(directory_path):
            print(f"Directory '{directory_name}' Checking ... ")
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    if file.endswith(".winlocker"):
                        input_file = os.path.join(root, file)
                        success_count, fail_count, failed_files = decrypt_file(input_file, password, success_count, fail_count, failed_files)
        else:
            print(f"Warning: Directory '{directory_name}'is not founded.")
    
    return success_count, fail_count, failed_files

def main():
    user_profile = str(Path.home())  
    base_input_path = user_profile
    password = "1337"  

    success_count, fail_count, failed_files = decrypt_specified_folders(base_input_path, password)

    print(f"\nDecryption is complete.")
    print(f"A total of {success_count} files were decrypted.")
    print(f"A total of {fail_count} files failed to be decrypted.")

    if fail_count > 0:
        print("\nList of files that failed to be decrypted:")
        for failed_file in failed_files:
            print(failed_file)

    remove_persistence()

    restore_background()

    input("The task is complete. Press Enter to exit the program.")

if __name__ == "__main__":
    main()
