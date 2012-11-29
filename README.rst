Replicon.Cryptography.SCrypt
----------------------------

This library is a wrapper for the scrypt key-deriviation function (http://www.tarsnap.com/scrypt.html) created by
Colin Percival.  The core of the library is a copy of the scrypt KDF routines written in C and distributed by Colin.
We've added a simple .NET wrapper class and done a bit of work to compile this into a mixed-mode .NET assembly.

Why a Mixed-Mode Assembly?
~~~~~~~~~~~~~~~~~~~~~~~~~~

Well, there is a function scrypt library for .NET in CryptSharp (http://www.zer7.com/software.php?page=cryptsharp).
But it's slow.  Now, scrypt is supposed to be slow... but it's supposed to be slow to brute force, not slow to
execute.  If you use a poor implementation of scrypt and tune your parameters to match that implementation, you'll
get a very false sense of security.

CryptSharp executes a hash with parameters (N=2^14, r=8, p=1) in about 1180ms.  This library performs the same hash
in about 70ms.  That's a huge and significant performance difference.

It'd be great to see a higher performance .NET implementation of scrypt.  Until that comes out, this mixed-mode
assembly using Colin's original scrypt implementation works pretty darn well.

Wrapper API
~~~~~~~~~~~

Psuedo-API description::

    namespace Replicon.Cryptography.SCrypt
    {
        public class SCrypt
        {
            public static String GenerateSalt();
            public static String GenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p,
                UInt32 hashLengthBytes);

            public static String HashPassword(String password);
            public static String HashPassword(String password, String salt);

            public static bool Verify(String password, String hash);

            public static Byte[] DeriveKey(Byte[] password, Byte[] salt, UInt64 N, UInt32 r, UInt32 p,
                UInt34 derivedKeyLengthBytes);
        }
    }
