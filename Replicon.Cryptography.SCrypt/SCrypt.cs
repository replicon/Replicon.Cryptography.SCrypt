
using System;

namespace Replicon.Cryptography.SCrypt
{
    public static class SCrypt
    {
        #region IPasswordHash instance

        private static IPasswordHash passwordHash;
        private static object passwordHashLock = new object();

        private static IPasswordHash PasswordHash
        {
            get
            {
                if (passwordHash != null)
                    return passwordHash;
                lock (passwordHashLock)
                {
                    if (passwordHash != null)
                        return passwordHash;
                    return passwordHash = Factory.CreatePasswordHash();
                }
            }
        }

        #endregion
        #region User interface

        /// <summary>Default value for saltLengthBytes used by parameterless GenerateSalt, currently 16 bytes.</summary>
        public static uint DefaultSaltLengthBytes
        {
            get { return PasswordHash.DefaultSaltLengthBytes; }
        }

        /// <summary>Default value for N used by parameterless GenerateSalt, currently 2^14.</summary>
        public static ulong Default_N
        {
            get { return PasswordHash.Default_N; }
        }

        /// <summary>Default value for r used by parameterless GenerateSalt, currently 8.</summary>
        public static uint Default_r
        {
            get { return PasswordHash.Default_r; }
        }

        /// <summary>Default value for p used by parameterless GenerateSalt, currently 1.</summary>
        public static uint Default_p
        {
            get { return PasswordHash.Default_p; }
        }

        /// <summary>Default value for hashLengthBytes used by parameterless GenerateSalt, currently 32 bytes.</summary>
        public static uint DefaultHashLengthBytes
        {
            get { return PasswordHash.DefaultHashLengthBytes; }
        }

        /// <summary>Generate a salt for use with HashPassword, selecting reasonable default values for scrypt
        /// parameters that are appropriate for an interactive login verification workflow.</summary>
        /// <remarks>Uses the default values in DefaultSaltLengthBytes, Default_N, Default_r, Default_r, and
        /// DefaultHashLengthBytes.</remarks>
        public static string GenerateSalt()
        {
            return PasswordHash.GenerateSalt();
        }

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
        public static string GenerateSalt(uint saltLengthBytes, ulong N, uint r, uint p, uint hashLengthBytes)
        {
            return PasswordHash.GenerateSalt(saltLengthBytes, N, r, p, hashLengthBytes);
        }

        /// <summary>Generate a password hash using a newly generated salt, with default salt parameters.</summary>
        /// <param name="password">A password to hash.</param>
        public static string HashPassword(string password)
        {
            return PasswordHash.HashPassword(password);
        }

        /// <summary>Attempt to parse the salt component of a salt or password and return the tuning parameters
        /// embedded in the salt.</summary>
        /// <param name="salt">Salt or hashed password to parse.</param>
        /// <param name="saltBytes">The randomly generated salt data.  The length will match saltLengthBytes from
        /// GenerateSalt.</param>
        /// <param name="N">Matching value for GenerateSalt's N parameter.</param>
        /// <param name="r">Matching value for GenerateSalt's r parameter.</param>
        /// <param name="p">Matching value for GenerateSalt's p parameter.</param>
        /// <param name="hashLengthBytes">The number of bytes to store the password hash in.</param>
        /// <returns>True if the parsing was successful, false otherwise.</returns>
        public static bool TryParseSalt(string salt, out byte[] saltBytes, out ulong N, out uint r, out uint p, out uint hashLengthBytes)
        {
            return PasswordHash.TryParseSalt(salt, out saltBytes, out N, out r, out p, out hashLengthBytes);
        }

        /// <summary>Parse the salt component of a salt or password and return the tuning parameters embedded in the
        /// salt.</summary>
        /// <exception cref="Replicon.Cryptography.SCrypt.SaltParseException">Throws SaltParseException if an error
        /// occurs while parsing the salt.</exception>
        /// <param name="salt">Salt or hashed password to parse.</param>
        /// <param name="saltBytes">The randomly generated salt data.  The length will match saltLengthBytes from
        /// GenerateSalt.</param>
        /// <param name="N">Matching value for GenerateSalt's N parameter.</param>
        /// <param name="r">Matching value for GenerateSalt's r parameter.</param>
        /// <param name="p">Matching value for GenerateSalt's p parameter.</param>
        /// <param name="hashLengthBytes">The number of bytes to store the password hash in.</param>
        public static void ParseSalt(string salt, out byte[] saltBytes, out ulong N, out uint r, out uint p, out uint hashLengthBytes)
        {
            PasswordHash.ParseSalt(salt, out saltBytes, out N, out r, out p, out hashLengthBytes);
        }

        /// <summary>Generate a password hash using a specific password salt.</summary>
        /// <param name="password">A password to hash.</param>
        /// <param name="salt">Salt to hash the password with.  This is often a password hash from a previous
        /// HashPassword call, which contains the salt of the original password call; in that case, the returned
        /// hash will be identical to the salt parameter if the password is the same password as the original.</param>
        public static string HashPassword(string password, string salt)
        {
            return PasswordHash.HashPassword(password, salt);
        }

        /// <summary>Verify that a given password matches a given hash.</summary>
        public static bool Verify(string password, string hash)
        {
            return PasswordHash.Verify(password, hash);
        }

        /// <summary>The 'raw' scrypt key-derivation function.</summary>
        /// <param name="password">The password bytes to generate the key based upon.</param>
        /// <param name="salt">Random salt bytes to make the derived key unique.</param>
        /// <param name="N">CPU/memory cost parameter.  Must be a value 2^N.  2^14 (16384) causes a calculation time
        /// of approximately 50-70ms on 2010 era hardware; each successive value (eg. 2^15, 2^16, ...) should
        /// double the amount of CPU time and memory required.</param>
        /// <param name="r">scrypt 'r' tuning parameter</param>
        /// <param name="p">scrypt 'p' tuning parameter (parallelization parameter); a large value of p can increase
        /// computational cost of scrypt without increasing the memory usage.</param>
        /// <param name="derivedKeyLengthBytes">The number of bytes of key to derive.</param>
        public static Byte[] DeriveKey(Byte[] password, Byte[] salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes)
        {
            return PasswordHash.DeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        #endregion
    }
}