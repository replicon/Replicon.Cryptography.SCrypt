
@echo off

set PATH=%PATH%;C:\MinGW\bin
gcc -c -g -O2 -msse -msse2 crypto_scrypt-sse.c
gcc -c -g -O2 -msse -msse2 memlimit.c
gcc -c -g -O2 -msse -msse2 scrypt_calibrate.c
gcc -c -g -O2 -msse -msse2 scrypt_ext.c
gcc -c -g -O2 -msse -msse2 scryptenc_cpuperf.c
gcc -c -g -O2 -msse -msse2 sha256.c

gcc -m32 -shared -o scrypt.dll crypto_scrypt-sse.o memlimit.o scrypt_calibrate.o scrypt_ext.o scryptenc_cpuperf.o sha256.o -Wl,--output-def,scrypt.def,--out-implib,scrypt.a
