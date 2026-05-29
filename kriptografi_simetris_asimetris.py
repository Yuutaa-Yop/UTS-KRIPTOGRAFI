import time
import sys
from cryptography.fernet import Fernet
import rsa

def test_symmetric_aes_fernet(plain_text):
    print("=== PENGUJIAN SIMETRIS (AES/FERNET) ===")
    bytes_text = plain_text.encode('utf-8')
    
    key = Fernet.generate_key()
    f = Fernet(key)
    
    start_enc = time.perf_counter()
    ciphertext = f.encrypt(bytes_text)
    end_enc = time.perf_counter()
    time_enc = end_enc - start_enc
    
    start_dec = time.perf_counter()
    decrypted_text = f.decrypt(ciphertext).decode('utf-8')
    end_dec = time.perf_counter()
    time_dec = end_dec - start_dec
    
    print(f"Ukuran Plaintext  : {len(bytes_text)} bytes")
    print(f"Ukuran Ciphertext : {len(ciphertext)} bytes")
    print(f"Waktu Enkripsi    : {time_enc:.6f} detik")
    print(f"Waktu Dekripsi    : {time_dec:.6f} detik")
    print(f"Hasil Dekripsi Match? {plain_text == decrypted_text}\n")
    
    return time_enc + time_dec, len(ciphertext)

def test_asymmetric_rsa(plain_text):
    print("=== PENGUJIAN ASIMETRIS (RSA) ===")
    bytes_text = plain_text.encode('utf-8')
    
    print("Generating RSA keys (2048-bit)...")
    (public_key, private_key) = rsa.newkeys(2048)
    
    start_enc = time.perf_counter()
    ciphertext = rsa.encrypt(bytes_text, public_key)
    end_enc = time.perf_counter()
    time_enc = end_enc - start_enc
    
    start_dec = time.perf_counter()
    decrypted_text = rsa.decrypt(ciphertext, private_key).decode('utf-8')
    end_dec = time.perf_counter()
    time_dec = end_dec - start_dec
    
    print(f"Ukuran Plaintext  : {len(bytes_text)} bytes")
    print(f"Ukuran Ciphertext : {len(ciphertext)} bytes")
    print(f"Waktu Enkripsi    : {time_enc:.6f} detik")
    print(f"Waktu Dekripsi    : {time_dec:.6f} detik")
    print(f"Hasil Dekripsi Match? {plain_text == decrypted_text}\n")
    
    return time_enc + time_dec, len(ciphertext)

if __name__ == "__main__":
    pesan_uji = "Struktur data dan keamanan informasi adalah hal penting."
    
    waktu_aes, ukuran_aes = test_symmetric_aes_fernet(pesan_uji)
    waktu_rsa, ukuran_rsa = test_asymmetric_rsa(pesan_uji)
    
    print("=========================================================")
    print("                  TABEL PERBANDINGAN                     ")
    print("=========================================================")
    print(f"{'Parameter':<25} | {'AES (Fernet)':<15} | {'RSA (2048-bit)':<15}")
    print("-" * 61)
    print(f"{'Total Kecepatan Proses':<25} | {waktu_aes:.6f} s | {waktu_rsa:.6f} s")
    print(f"{'Ukuran Ciphertext':<25} | {ukuran_aes} bytes | {ukuran_rsa} bytes")
    print(f"{'Tingkat Keamanan Dasar':<25} | Sangat Tinggi    | Tinggi (Rentan Ukuran)")
    print("=========================================================")