import os
import zipfile
import py_compile
import shutil

# --- CONFIGURATION ---
SOURCE_DIR = r"D:\ML_Data\malware"  # Where you downloaded theZoo
OUTPUT_DIR = r"D:\ML_Data\malware_ready" # Where raw EXEs will go
PASSWORD = b"infected"

def setup():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"[+] Created output directory: {OUTPUT_DIR}")

def unpack_thezoo():
    print(f"[*] Scanning {SOURCE_DIR} for malware archives...")
    count = 0
    
    for root, dirs, files in os.walk(SOURCE_DIR):
        for file in files:
            if file.endswith(".zip"):
                zip_path = os.path.join(root, file)
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        # Extract all files in the zip
                        for member in zf.namelist():
                            # Skip MacOS/Linux junk if possible
                            if member.startswith("__MACOSX"): continue
                            
                            # Read the raw bytes using the password
                            try:
                                data = zf.read(member, pwd=PASSWORD)
                                
                                # Basic check: Is it an executable (MZ header)?
                                if data.startswith(b'MZ'):
                                    # Save to flat directory with unique name
                                    safe_name = f"malware_{count}.bin" 
                                    out_path = os.path.join(OUTPUT_DIR, safe_name)
                                    
                                    with open(out_path, "wb") as f:
                                        f.write(data)
                                    
                                    count += 1
                                    print(f"    [+] Extracted: {member} -> {safe_name}")
                            except Exception as e:
                                # Often zip passwords might vary or file is corrupt, skip
                                pass
                except Exception as e:
                    print(f"    [!] Failed to open {file}: {e}")

    print(f"\n[SUCCESS] Extracted {count} live malware samples to {OUTPUT_DIR}")

if __name__ == "__main__":
    setup()
    unpack_thezoo()