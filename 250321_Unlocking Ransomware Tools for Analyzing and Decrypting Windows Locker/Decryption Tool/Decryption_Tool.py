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
        raise ValueError("패딩 제거에 실패하였습니다. (비밀번호가 다르거나 데이터가 손상되었을 수 있습니다)")

    return plaintext

def remove_persistence():
    local_app_data = os.environ.get("LOCALAPPDATA")
    discord_path = os.path.join(local_app_data, "discord.exe")
    
    if os.path.exists(discord_path):
        os.remove(discord_path)
        print(f"자가복제된 파일 '{discord_path}' 삭제되었습니다.")

    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
        winreg.DeleteValue(reg_key, "discord")
        winreg.CloseKey(reg_key)
        print("레지스트리에서 'discord' 지속성 항목이 삭제되었습니다.")
    except FileNotFoundError:
        print("레지스트리에서 'discord' 항목을 찾을 수 없습니다.")
    except Exception as e:
        print(f"레지스트리에서 'discord' 항목 삭제에 실패했습니다: {e}")

def restore_background():
    try:
        appdata_path = os.environ.get("APPDATA")  
        old_wallpaper_path = os.path.join(appdata_path, "fondo_antiguo.jpg")

        if os.path.exists(old_wallpaper_path):
            ctypes.windll.user32.SystemParametersInfoW(20, 0, old_wallpaper_path, 3)
            print(f"원래 배경화면 '{old_wallpaper_path}'으로 복원되었습니다.")
        else:
            print("원래 배경화면 파일을 찾을 수 없습니다.")
    except Exception as e:
        print(f"배경화면 복원에 실패했습니다: {e}")

def decrypt_file(input_file: str, password: str, success_count: int, fail_count: int, failed_files: list):
    with open(input_file, "rb") as f:
        ciphertext = f.read()

    try:
        plaintext = decrypt_aes(ciphertext, password)
    except Exception as e:
        print(f"{input_file} 복호화에 실패했습니다:", e)
        fail_count += 1
        failed_files.append(input_file) 
        return success_count, fail_count, failed_files


    output_file = os.path.splitext(input_file)[0]  
    
    with open(output_file, "wb") as f:
        f.write(plaintext)

    os.remove(input_file)

    print(f"{input_file} 복호화에 성공했습니다. 결과는 '{output_file}'에 저장되었습니다.")
    
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
            print(f"폴더 '{directory_name}' 탐색 중...")
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    if file.endswith(".winlocker"):
                        input_file = os.path.join(root, file)
                        success_count, fail_count, failed_files = decrypt_file(input_file, password, success_count, fail_count, failed_files)
        else:
            print(f"경고: 폴더 '{directory_name}'이(가) 존재하지 않습니다.")
    
    return success_count, fail_count, failed_files

def main():
    user_profile = str(Path.home())  
    base_input_path = user_profile
    password = "1337"  

    success_count, fail_count, failed_files = decrypt_specified_folders(base_input_path, password)

    print(f"\n복호화가 완료되었습니다.")
    print(f"총 {success_count}개의 파일이 복호화되었습니다.")
    print(f"총 {fail_count}개의 파일이 복호화에 실패했습니다.")

    if fail_count > 0:
        print("\n복호화 실패한 파일 목록:")
        for failed_file in failed_files:
            print(failed_file)

    remove_persistence()

    restore_background()

    input("작업이 완료되었습니다. 프로그램을 종료하려면 엔터를 누르세요.")

if __name__ == "__main__":
    main()
