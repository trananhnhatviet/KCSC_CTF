# CFB64
![image](https://github.com/trananhnhatviet/KCSC_CTF/assets/92376163/0d3617a2-aeee-481b-9008-f6e40411663d)

-   Source code của chall như sau:
```
import time
import sys
import os
from Crypto.Cipher import AES

flag = os.environ.get("FLAG", b"KCSC{FAKE_FLAGGGGGGGGGGGGGGGGGGGGGG}")

key = os.urandom(16)
iv = os.urandom(16)

def encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=64)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

print(f'encrypted_flag = {encrypt(key, iv, flag).hex()}')

for _ in range(23):
    plaintext = bytes.fromhex(input("plaintext: "))
    print(f'ciphertext = {encrypt(key, iv, plaintext).hex()}')
```

-   Nhìn source code, ta thấy rằng challenge này là dạng AES chế độ CFB (Cipher Feedback)

-   Sau khi netcat, ta sẽ thu được 1 đoạn mã hexa, đó chính là mã hóa Flag với key và iv được random 16 byte
-   Ngoài ra, khi ta nhập được 1 đoạn plaintext tự chọn, ta sẽ thu được ciphertext tương ứng với key và iv đó
-   Trước hết, ta cần tìm hiểu rõ mã hóa CFB như thế nào
![image](https://github.com/trananhnhatviet/KCSC_CTF/assets/92376163/47d76b04-fc96-4957-8fe1-dc4cb0e150e9)

-   Ta thấy rằng ở block đầu ``Plaintext ⊕ Key(IV)  = Ciphertext``, ta cần 1 chosen_plaintext 16 byte để gửi vào server, khi đó, ta sẽ thu được ``chosen_ciphertext = chosen_plaintext ⊕ Key(IV)``
-    Sau đó, ta sẽ để ``Ciphertext ⊕ chosen_ciphertext = Plaintext ⊕ Key(IV) ⊕ chosen_plaintext ⊕ Key(IV) = Plaintext ⊕ chosen_plaintext``, và để thu được Plaintext, ta chỉ cần ⊕ với chosen_plaintext là được thuiiiii 
-    Mình sẽ chọn ``chosen_plaintext = b'this_is_a_fakeee'`` và rồi đổi ra hexa là ``chosen_plaintext_hex = '746869735f69735f615f66616b656565'``, sau đó netcat tới server và thu được như sau:
![image](https://github.com/trananhnhatviet/KCSC_CTF/assets/92376163/4d222139-a550-4d1e-a86d-6f802e31757b)

-    Đoạn code sẽ như sau:
```
chosen_plaintext = b'this_is_a_fakeee' # 1 đoạn tự chọn để gửi tới server
chosen_plaintext_hex = '746869735f69735f615f66616b656565' # Đổi sang hexa
encrypted_flag_hex = 'c77d8764bf1092bfa8299c835dbab64d9b6d2ef613837e573cd1c556fe779c9c03846694c78a0122331fbae8e2ad1ad7'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:16] # Lấy 16 byte đầu tiên
chosen_ciphertext_hex = 'f856bd549b2ad1bf8de5d6cd9204f71a'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))
```
-    Output của đoạn code này là ``b'KCSC{S0_D\x93,/\xa4\xdb$2'``, ta thu được 1 phần ``FLAG = KCSC{S0_``
-    Vì IV của block sau chính là ciphertext của block trước, và để thu được chính xác thì ta cần phải chọn chosen_plaintext sao cho đoạn đầu là 1 phần của FLAG, ta chọn ``chosen_plaintext = b'KCSC{S0_12345678'``
-    Tiếp tục netcat tới server, ta thu được như sau:
![image](https://github.com/trananhnhatviet/KCSC_CTF/assets/92376163/262ace9f-39da-4832-b6f9-9dab72d2c758)

-    Đoạn code sẽ như sau:
```
chosen_plaintext = b'KCSC{S0_12345678'
chosen_plaintext_hex = '4b4353437b53305f3132333435363738' # Đổi sang hexa
encrypted_flag_hex = 'ead71fe2111396ea15651069a2f50dc043a4d1e934d8e5aedfbe5be23ea045f2a54234a37b2ab1f090b5a343c3803854'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:16]
chosen_ciphertext_hex = 'ead71fe2111396ea68674d64c8e565ab'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))
```
-    Tiếp tục làm như các bước ở trên, ta sẽ thu được FLAG cần tìm
-    Đoạn code sẽ như sau:
```
from pwn import xor

chosen_plaintext = b'this_is_a_fakeee' # 1 đoạn tự chọn để gửi tới server
chosen_plaintext_hex = '746869735f69735f615f66616b656565' # Đổi sang hexa
encrypted_flag_hex = 'c77d8764bf1092bfa8299c835dbab64d9b6d2ef613837e573cd1c556fe779c9c03846694c78a0122331fbae8e2ad1ad7'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:16]
chosen_ciphertext_hex = 'f856bd549b2ad1bf8de5d6cd9204f71a'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))

chosen_plaintext = b'KCSC{S0_12345678'
chosen_plaintext_hex = '4b4353437b53305f3132333435363738' # Đổi sang hexa
encrypted_flag_hex = 'ead71fe2111396ea15651069a2f50dc043a4d1e934d8e5aedfbe5be23ea045f2a54234a37b2ab1f090b5a343c3803854'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:16]
chosen_ciphertext_hex = 'ead71fe2111396ea68674d64c8e565ab'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))

chosen_plaintext = b'KCSC{S0_L0n9_&_S1234567812345678'
chosen_plaintext_hex = '4b4353437b53305f4c306e395f265f5331323334353637383132333435363738' # Đổi sang hexa
encrypted_flag_hex = 'a13babd4dba23f122cdb3cda7f819837f6deb46c6840aaeb8096e74e455519d353f6632d05175ac095e2bedbdc51f0ff'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:32]
chosen_ciphertext_hex = 'a13babd4dba23f122cdb3cda7f819837f7b3e239270fc2b0db0f92c3a74e5d55'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))

chosen_plaintext = b'KCSC{S0_L0n9_&_S0_eazy_c12345678'
chosen_plaintext_hex = '4b4353437b53305f4c306e395f265f53305f65617a795f633132333435363738' # Đổi sang hexa
encrypted_flag_hex = '2859edf61cea90fb0e4b750a106fd665bd7633f833c66eb6f3853cbeb6957f079070212edb29b4109a8be28bfa5fcd8a'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:32]
chosen_ciphertext_hex = '2859edf61cea90fb0e4b750a106fd665bd7633f833c66eb6aad87cefedcd174f'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))

chosen_plaintext = b'KCSC{S0_L0n9_&_S0_eazy_chosenn_p1234567812345678'
chosen_plaintext_hex = '4b4353437b53305f4c306e395f265f53305f65617a795f63686f73656e6e5f7031323334353637383132333435363738' # Đổi sang hexa
encrypted_flag_hex = '4d5583b433076780f8dca6a41fb036a4fdfb5d965f5012bfaa8cc201078dadec770943a0cb9466e9ab77866dc4117db3'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:64]
chosen_ciphertext_hex = '4d5583b433076780f8dca6a41fb036a4fdfb5d965f5012bfaa8cc201078dadec2a5a19fa8ac729a54e33e33c2df45e52'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))

chosen_plaintext = b'KCSC{S0_L0n9_&_S0_eazy_chosenn_plaintext12345678'
chosen_plaintext_hex = '4b4353437b53305f4c306e395f265f53305f65617a795f63686f73656e6e5f706c61696e746578743132333435363738' # Đổi sang hexa
encrypted_flag_hex = 'd9f04d614f7abb31c03102d426f6554e74bf12e95c40471de64b8cf65311a77f68a3fbccf4e45457158dff7cd8747158'
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext = encrypted_flag[:64]
chosen_ciphertext_hex = 'd9f04d614f7abb31c03102d426f6554e74bf12e95c40471de64b8cf65311a77f68a3fbccf4e454577bdeb83c8c212d1d'
chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
print(xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))
```
-    Lúc đó mình run quá nên làm theo cách như này, ngoài ra mình có thể sử dụng pwntool để hoàn thành bài này
-    Đoạn code dùng pwntool sẽ như sau:
```
from pwn import*
FLAG = b''
count = 0
for i in range(6):
    if len(FLAG) %16 ==0:
        FLAG = FLAG + b'*'
        count = count + 1
    io = remote('188.166.220.129', 60124)
    io.recvuntil(b'encrypted_flag = ')
    encrypted_flag_hex = (io.recvuntil(b'\n',drop=True).decode())
    encrypted_flag = bytes.fromhex(encrypted_flag_hex)
    ciphertext = encrypted_flag[:16*(count)]
    chosen_plaintext = FLAG
    while len(chosen_plaintext)%16 !=0:
        chosen_plaintext = chosen_plaintext + b'*'
    chosen_plaintext_hex = chosen_plaintext.hex()
    io.sendlineafter(b'plaintext: ',chosen_plaintext_hex)
    io.recvuntil(b'ciphertext = ')
    chosen_ciphertext_hex = (io.recvuntil(b'\n',drop=True).decode())
    chosen_ciphertext = bytes.fromhex(chosen_ciphertext_hex)
    flag = (xor(xor(chosen_ciphertext,ciphertext),chosen_plaintext))[:8*(i+1)]
    FLAG = flag
print(FLAG)
```
Flag của challenge này là: **KCSC{S0_L0n9_&_S0_eazy_chosenn_plaintext_attack}**
