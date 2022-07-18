using System;
using System.Security.Cryptography;

namespace Replicon.Cryptography.SCrypt
{
    // NOTE: The below code is copied from Vinicius Chiele's Scrypt library(https://github.com/viniciuschiele/Scrypt).
    // The project has an Apache License 2.0(https://github.com/viniciuschiele/Scrypt/blob/master/LICENSE) which allows us
    // to use the code here.
    // FIXME: Use https://github.com/viniciuschiele/Scrypt as a dependency after PR #11 is released.
    class KeyDerivationFunction : IKeyDerivationFunction
    {
        public byte[] DeriveKey(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes)
        {
            return CryptoScrypt(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        private unsafe static void BulkCopy(void* dst, void* src, uint len)
        {
            byte* ptr = (byte*)dst;
            byte* ptr2 = (byte*)src;
            while (len >= 8)
            {
                *(long*)ptr = *(long*)ptr2;
                ptr += 8;
                ptr2 += 8;
                len -= 8;
            }

            if (len >= 4)
            {
                *(uint*)ptr = *(uint*)ptr2;
                ptr += 4;
                ptr2 += 4;
                len -= 4;
            }

            if (len >= 2)
            {
                *(ushort*)ptr = *(ushort*)ptr2;
                ptr += 2;
                ptr2 += 2;
                len -= 2;
            }

            if (len >= 1)
            {
                *ptr = *ptr2;
            }
        }

        private unsafe static void BulkXor(void* dst, void* src, uint len)
        {
            byte* ptr = (byte*)dst;
            byte* ptr2 = (byte*)src;
            while (len >= 8)
            {
                *(long*)ptr ^= *(long*)ptr2;
                ptr += 8;
                ptr2 += 8;
                len -= 8;
            }

            if (len >= 4)
            {
                *(int*)ptr ^= (int)(*(uint*)ptr2);
                ptr += 4;
                ptr2 += 4;
                len -= 4;
            }

            if (len >= 2)
            {
                byte* intPtr = ptr;
                *(ushort*)intPtr = (ushort)(*(ushort*)intPtr ^ *(ushort*)ptr2);
                ptr += 2;
                ptr2 += 2;
                len -= 2;
            }

            if (len >= 1)
            {
                byte* intPtr2 = ptr;
                *intPtr2 = (byte)(*intPtr2 ^ *ptr2);
            }
        }

        private unsafe static void Encode32(byte* p, uint x)
        {
            *p = (byte)(x & 0xFF);
            p[1] = (byte)((x >> 8) & 0xFF);
            p[2] = (byte)((x >> 16) & 0xFF);
            p[3] = (byte)((x >> 24) & 0xFF);
        }

        private unsafe static uint Decode32(byte* p)
        {
            return (uint)(*p + (p[1] << 8) + (p[2] << 16) + (p[3] << 24));
        }

        private unsafe static void Salsa208(uint* B)
        {
            uint num = *B;
            uint num2 = B[1];
            uint num3 = B[2];
            uint num4 = B[3];
            uint num5 = B[4];
            uint num6 = B[5];
            uint num7 = B[6];
            uint num8 = B[7];
            uint num9 = B[8];
            uint num10 = B[9];
            uint num11 = B[10];
            uint num12 = B[11];
            uint num13 = B[12];
            uint num14 = B[13];
            uint num15 = B[14];
            uint num16 = B[15];
            for (int i = 0; i < 8; i += 2)
            {
                num5 ^= R(num + num13, 7);
                num9 ^= R(num5 + num, 9);
                num13 ^= R(num9 + num5, 13);
                num ^= R(num13 + num9, 18);
                num10 ^= R(num6 + num2, 7);
                num14 ^= R(num10 + num6, 9);
                num2 ^= R(num14 + num10, 13);
                num6 ^= R(num2 + num14, 18);
                num15 ^= R(num11 + num7, 7);
                num3 ^= R(num15 + num11, 9);
                num7 ^= R(num3 + num15, 13);
                num11 ^= R(num7 + num3, 18);
                num4 ^= R(num16 + num12, 7);
                num8 ^= R(num4 + num16, 9);
                num12 ^= R(num8 + num4, 13);
                num16 ^= R(num12 + num8, 18);
                num2 ^= R(num + num4, 7);
                num3 ^= R(num2 + num, 9);
                num4 ^= R(num3 + num2, 13);
                num ^= R(num4 + num3, 18);
                num7 ^= R(num6 + num5, 7);
                num8 ^= R(num7 + num6, 9);
                num5 ^= R(num8 + num7, 13);
                num6 ^= R(num5 + num8, 18);
                num12 ^= R(num11 + num10, 7);
                num9 ^= R(num12 + num11, 9);
                num10 ^= R(num9 + num12, 13);
                num11 ^= R(num10 + num9, 18);
                num13 ^= R(num16 + num15, 7);
                num14 ^= R(num13 + num16, 9);
                num15 ^= R(num14 + num13, 13);
                num16 ^= R(num15 + num14, 18);
            }

            *B += num;
            B[1] += num2;
            B[2] += num3;
            B[3] += num4;
            B[4] += num5;
            B[5] += num6;
            B[6] += num7;
            B[7] += num8;
            B[8] += num9;
            B[9] += num10;
            B[10] += num11;
            B[11] += num12;
            B[12] += num13;
            B[13] += num14;
            B[14] += num15;
            B[15] += num16;
        }

        private static uint R(uint a, int b)
        {
            return (a << b) | (a >> 32 - b);
        }

        private unsafe static void BlockMix(uint* Bin, uint* Bout, uint* X, uint r)
        {
            BulkCopy(X, Bin + (2 * r - 1) * 16, 64);
            for (int i = 0; i < 2 * r; i += 2)
            {
                BulkXor(X, Bin + i * 16, 64);
                Salsa208(X);
                BulkCopy(Bout + i * 8, X, 64);
                BulkXor(X, Bin + (i * 16 + 16), 64);
                Salsa208(X);
                BulkCopy(Bout + (i * 8 + r * 16), X, 64);
            }
        }

        private unsafe static ulong Integerify(uint* B, uint r)
        {
            uint* ptr = (uint*)((byte*)B + (2 * r - 1) * 64);
            return (((ulong)ptr[1] << 32) + *ptr);
        }

        private unsafe static void SMix(byte* B, uint r, ulong N, uint* V, uint* XY)
        {
            uint* ptr = XY + 32 * r;
            uint* x = XY + 64 * r;
            for (int i = 0; i < 32 * r; i++)
            {
                XY[i] = Decode32(B + 4 * i);
            }

            for (ulong num = 0L; num < N; num += 2)
            {
                BulkCopy(V + num * (32 * r), XY, 128 * r);
                BlockMix(XY, ptr, x, r);
                BulkCopy(V + (num + 1) * (32 * r), ptr, 128 * r);
                BlockMix(ptr, XY, x, r);
            }

            for (uint j = 0; j < N; j += 2)
            {
                ulong num2 = Integerify(XY, r) & (N - 1);
                BulkXor(XY, V + num2 * (32 * r), 128 * r);
                BlockMix(XY, ptr, x, r);
                num2 = (Integerify(ptr, r) & (N - 1));
                BulkXor(ptr, V + num2 * (32 * r), 128 * r);
                BlockMix(ptr, XY, x, r);
            }

            for (int k = 0; k < 32 * r; k++)
            {
                Encode32(B + 4 * k, XY[k]);
            }
        }

        private unsafe static byte[] CryptoScrypt(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes)
        {
            byte[] array = new byte[128 * r * p + 63];
            byte[] array2 = new byte[256 * r + 63];
            byte[] array3 = new byte[128 * r * N + 63];
            byte[] array4 = new byte[derivedKeyLengthBytes];
            HMACSHA256 mac = new HMACSHA256(password);
            PBKDF2_SHA256(mac, password, salt, (uint)salt.Length, 1L, array, p * 128 * r);
            fixed (byte* ptr = array)
            {
                fixed (byte* v_temp = array3)
                {
                    IntPtr* v = (IntPtr*)v_temp;
                    fixed (byte* xY_temp = array2)
                    {
                        IntPtr* xY = (IntPtr*)xY_temp;
                        for (int i = 0; i < p; i++)
                        {
                            SMix(ptr + i * 128 * r, r, N, (uint*)v, (uint*)xY);
                        }
                    }
                }
            }

            PBKDF2_SHA256(mac, password, array, p * 128 * r, 1L, array4, derivedKeyLengthBytes);
            return array4;
        }

        private static void PBKDF2_SHA256(HMACSHA256 mac, byte[] password, byte[] salt, uint saltLength, long iterationCount, byte[] derivedKey, uint derivedKeyLength)
        {
            if ((double)derivedKeyLength > (Math.Pow(2.0, 32.0) - 1.0) * 32.0)
            {
                throw new ArgumentException("Requested key length too long");
            }

            byte[] array = new byte[32];
            byte[] array2 = new byte[32];
            byte[] array3 = new byte[saltLength + 4];
            uint num = (uint)Math.Ceiling((double)derivedKeyLength / 32.0);
            uint num2 = derivedKeyLength - (num - 1) * 32;
            Buffer.BlockCopy(salt, 0, array3, 0, (int)saltLength);
            using (IncrementalHash incrementalHash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, mac.Key))
            {
                for (int i = 1; i <= num; i++)
                {
                    array3[saltLength] = (byte)(i >> 24);
                    array3[saltLength + 1] = (byte)(i >> 16);
                    array3[saltLength + 2] = (byte)(i >> 8);
                    array3[saltLength + 3] = (byte)i;
                    mac.Initialize();
                    incrementalHash.AppendData(array3, 0, array3.Length);
                    Buffer.BlockCopy(incrementalHash.GetHashAndReset(), 0, array, 0, array.Length);
                    Buffer.BlockCopy(array, 0, array2, 0, 32);
                    for (long num3 = 1L; num3 < iterationCount; num3++)
                    {
                        incrementalHash.AppendData(array, 0, array.Length);
                        Buffer.BlockCopy(incrementalHash.GetHashAndReset(), 0, array, 0, array.Length);
                        for (int j = 0; j < 32; j++)
                        {
                            array2[j] ^= array[j];
                        }
                    }

                    Buffer.BlockCopy(array2, 0, derivedKey, (i - 1) * 32, (i == num) ? (int)num2 : 32);
                }
            }
        }

        private static bool SafeEquals(string a, string b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            uint num = 0u;
            for (int i = 0; i < a.Length; i++)
            {
                num |= (uint)(a[i] ^ b[i]);
            }

            return num == 0;
        }
    }
}
