#pragma once

using namespace System;

namespace SCryptMMA
{
    /// <summary>A .NET wrapper for a native implementation of the scrypt key-derivation function.  In addition to
    /// exposing the raw key-derivation function (DerivePassword), SCrypt also contains helper functions for a common
    /// use-case of scrypt as a password hashing algorithm.</summary>
    public ref class SCrypt abstract sealed
    {
    public:
        /// <summary>Generate a salt for use with HashPassword, selecting reasonable default values for scrypt
        /// parameters that are appropriate for an interactive login verification workflow.</summary>
        /// <remarks>Default values are: saltLengthBytes -> 16, N -> 2^14, r -> 8, p -> 1,
        /// hashLengthBytes -> 32.</remarks>
        static String^ GenerateSalt();

        /// <summary>Generate a random salt for use with HashPassword.  In addition to the random salt, the salt value
        /// also contains the tuning parameters to use with the scrypt algorithm, as well as the size of the password
        /// hash to generate.</summary>
        /// <param name="saltLengthBytes">The number of bytes of random salt to generate.  The goal for the salt is
        /// to be unique.  16 bytes gives a 2^128 possible salt options, and roughly an N in 2^64 chance of a salt
        /// collision for N salts, which seems reasonable.  A larger salt requires more storage space, but doesn't
        /// affect the scrypt performance significantly.</param>
        /// <param name="N">CPU/memory cost parameter.  Must be a value 2^N.  2^14 (16384) causes a calculation time
        /// of approximately 50-70ms on 2010 era hardware; each successive value (eg. 2^15, 2^16, ...) should
        /// double the amount of CPU time and memory required.</param>
        /// <param name="r">scrypt 'r' tuning parameter</param>
        /// <param name="p">scrypt 'p' tuning parameter (parallelization parameter); a large value of p can increase
        /// computational cost of scrypt without increasing the memory usage.</param>
        /// <param name="hashLengthBytes">The number of bytes to store the password hash in.</param>
        static String^ GenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p, UInt32 hashLengthBytes);

        /// <summary>Generate a password hash using a newly generated salt, with default salt parameters.</summary>
        /// <param name="password">A password to hash.</param>
        static String^ HashPassword(String^ password);

        /// <summary>Generate a password hash using a specific password salt.</summary>
        /// <param name="password">A password to hash.</param>
        /// <param name="salt">Salt to hash the password with.  This is often a password hash from a previous
        /// HashPassword call, which contains the salt of the original password call; in that case, the returned
        /// hash will be identical to the salt parameter if the password is the same password as the original.</param>
        static String^ HashPassword(String^ password, String^ salt);

        /// <summary>Verify that a given password matches a given hash.</summary>
        static bool Verify(String^ password, String^ hash);

        /// <summary>The 'raw' scrypt key-derivation function.</summary>
        /// <param name="N">CPU/memory cost parameter.  Must be a value 2^N.  2^14 (16384) causes a calculation time
        /// of approximately 50-70ms on 2010 era hardware; each successive value (eg. 2^15, 2^16, ...) should
        /// double the amount of CPU time and memory required.</param>
        /// <param name="r">scrypt 'r' tuning parameter</param>
        /// <param name="p">scrypt 'p' tuning parameter (parallelization parameter); a large value of p can increase
        /// computational cost of scrypt without increasing the memory usage.</param>
        /// <param name="derivedKeyLengthBytes">The number of bytes of key to derive.</param>
        static array<Byte>^ DeriveKey(array<Byte>^ password, array<Byte>^ salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes);
    };
}
