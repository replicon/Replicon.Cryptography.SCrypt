
namespace Replicon.Cryptography.SCrypt
{/// <summary>Wrapper for the scrypt key-derivation function that provides helper functions for a common use-case
 /// of scrypt as a password hashing algorithm.</summary>
    public interface IPasswordHash : IKeyDerivationFunction
    {
        /// <summary>Default value for saltLengthBytes used by parameterless GenerateSalt, currently 16 bytes.</summary>
        uint DefaultSaltLengthBytes { get; }

        /// <summary>Default value for N used by parameterless GenerateSalt, currently 2^14.</summary>
        ulong Default_N { get; }

        /// <summary>Default value for r used by parameterless GenerateSalt, currently 8.</summary>
        uint Default_r { get; }

        /// <summary>Default value for p used by parameterless GenerateSalt, currently 1.</summary>
        uint Default_p { get; }

        /// <summary>Default value for hashLengthBytes used by parameterless GenerateSalt, currently 32 bytes.</summary>
        uint DefaultHashLengthBytes { get; }

        /// <summary>Generate a salt for use with HashPassword, selecting reasonable default values for scrypt
        /// parameters that are appropriate for an interactive login verification workflow.</summary>
        /// <remarks>Uses the default values in DefaultSaltLengthBytes, Default_N, Default_r, Default_r, and
        /// DefaultHashLengthBytes.</remarks>
        string GenerateSalt();

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
        string GenerateSalt(uint saltLengthBytes, ulong N, uint r, uint p, uint hashLengthBytes);

        /// <summary>Generate a password hash using a newly generated salt, with default salt parameters.</summary>
        /// <param name="password">A password to hash.</param>
        string HashPassword(string password);

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
        bool TryParseSalt(string salt, out byte[] saltBytes, out ulong N, out uint r, out uint p, out uint hashLengthBytes);

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
        void ParseSalt(string salt, out byte[] saltBytes, out ulong N, out uint r, out uint p, out uint hashLengthBytes);

        /// <summary>Generate a password hash using a specific password salt.</summary>
        /// <param name="password">A password to hash.</param>
        /// <param name="salt">Salt to hash the password with.  This is often a password hash from a previous
        /// HashPassword call, which contains the salt of the original password call; in that case, the returned
        /// hash will be identical to the salt parameter if the password is the same password as the original.</param>
        string HashPassword(string password, string salt);

        /// <summary>Verify that a given password matches a given hash.</summary>
        bool Verify(string password, string hash);
    }
}
