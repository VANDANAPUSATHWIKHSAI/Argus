import urllib.request
import zipfile
import os

url = "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
dest_dir = r"d:\ARGUS\external_tools\symbols"
zip_path = os.path.join(dest_dir, "windows.zip")

print("Ensuring directory exists...")
os.makedirs(dest_dir, exist_ok=True)

print(f"Downloading symbols from {url}...")
urllib.request.urlretrieve(url, zip_path)
print("Download complete.")

print("Extracting symbols...")
with zipfile.ZipFile(zip_path, 'r') as zip_ref:
    zip_ref.extractall(dest_dir)
print("Extraction complete.")

print("Cleaning up...")
os.remove(zip_path)
print("Done!")
