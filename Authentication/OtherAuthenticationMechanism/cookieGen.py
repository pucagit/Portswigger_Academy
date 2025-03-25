import hashlib
import base64

def process_passwords(file_path, output_file):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            passwords = file.readlines()
        
        processed_passwords = []
        for password in passwords:
            password = password.strip()
            md5_hashed = hashlib.md5(password.encode()).hexdigest()
            combined = "carlos:" + md5_hashed
            base64_encoded = base64.b64encode(combined.encode()).decode()
            processed_passwords.append(base64_encoded)
        
        with open(output_file, 'w', encoding='utf-8') as out_file:
            for encoded_password in processed_passwords:
                out_file.write(encoded_password + '\n')
        
        print(f"Processed passwords saved to {output_file}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    file_path = "../passwords.txt" 
    output_file = "cookie.txt"  
    process_passwords(file_path, output_file)
