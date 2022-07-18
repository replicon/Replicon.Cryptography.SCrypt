using System;
using System.Security.Cryptography;
using System.Text;

namespace Replicon.Cryptography.SCrypt
{
    class DefaultPasswordHash : IPasswordHash
    {
        private readonly IKeyDerivationFunction kdf;

        public DefaultPasswordHash(IKeyDerivationFunction kdf)
        {
            this.kdf = kdf;
        }

        #region Random number generator

        private RandomNumberGenerator randomGenerator;
        private object randomGeneratorLock = new object();

        private RandomNumberGenerator RandomGenerator
        {
            get
            {
                if (randomGenerator != null)
                    return randomGenerator;

                lock (randomGeneratorLock)
                {
                    if (randomGenerator != null)
                        return randomGenerator;
                    return randomGenerator = RandomNumberGenerator.Create();
                }
            }
        }

        #endregion
        #region IPasswordHash Members

        public uint DefaultSaltLengthBytes
        {
            get { return 16; }
        }

        public ulong Default_N
        {
            get { return 16384; }
        }

        public uint Default_r
        {
            get { return 8; }
        }

        public uint Default_p
        {
            get { return 1; }
        }

        public uint DefaultHashLengthBytes
        {
            get { return 32; }
        }

        public string GenerateSalt()
        {
            return GenerateSalt(DefaultSaltLengthBytes, Default_N, Default_r, Default_p, DefaultHashLengthBytes);
        }

        public string GenerateSalt(uint saltLengthBytes, ulong N, uint r, uint p, uint hashLengthBytes)
        {
            var salt = new byte[saltLengthBytes];
            RandomGenerator.GetBytes(salt);

            StringBuilder builder = new StringBuilder();
            builder.Append("$scrypt$");
            builder.Append(N);
            builder.Append("$");
            builder.Append(r);
            builder.Append("$");
            builder.Append(p);
            builder.Append("$");
            builder.Append(hashLengthBytes);
            builder.Append("$");
            builder.Append(Convert.ToBase64String(salt));
            builder.Append("$");
            return builder.ToString();
        }

        public string HashPassword(string password)
        {
            return HashPassword(password, GenerateSalt());
        }

        private static SaltParseException InternalTryParseSalt(string salt, out byte[] saltBytes, out ulong N, out uint r, out uint p, out uint hashLengthBytes)
        {
            saltBytes = null;
            N = 0;
            r = p = 0;
            hashLengthBytes = 0;

            var saltComponents = salt.Split('$');
            if (saltComponents.Length != 8)
                return new SaltParseException("Expected 8 dollar-sign ($) delimited salt components");
            else if (saltComponents[0] != "" || saltComponents[1] != "scrypt")
                return new SaltParseException("Expected $scrypt$");

            if (!ulong.TryParse(saltComponents[2], out N))
                return new SaltParseException("Failed to parse N parameter");
            else if (!uint.TryParse(saltComponents[3], out r))
                return new SaltParseException("Failed to parse r parameter");
            else if (!uint.TryParse(saltComponents[4], out p))
                return new SaltParseException("Failed to parse p parameter");
            else if (!uint.TryParse(saltComponents[5], out hashLengthBytes))
                return new SaltParseException("Failed to parse hashLengthBytes parameter");

            saltBytes = Convert.FromBase64String(saltComponents[6]);

            return null;
        }

        public bool TryParseSalt(string salt, out byte[] saltBytes, out ulong N, out uint r, out uint p, out uint hashLengthBytes)
        {
            var error = InternalTryParseSalt(salt, out saltBytes, out N, out r, out p, out hashLengthBytes);
            return error == null;
        }

        public void ParseSalt(string salt, out byte[] saltBytes, out ulong N, out uint r, out uint p, out uint hashLengthBytes)
        {
            var error = InternalTryParseSalt(salt, out saltBytes, out N, out r, out p, out hashLengthBytes);
            if (error != null)
                throw error;
        }

        public string HashPassword(string password, string salt)
        {
            ulong N;
            uint r;
            uint p;
            uint hashLengthBytes;
            byte[] salt_data;

            ParseSalt(salt, out salt_data, out N, out r, out p, out hashLengthBytes);

            var password_data = Encoding.UTF8.GetBytes(password);
            var hash_data = DeriveKey(password_data, salt_data, N, r, p, hashLengthBytes);

            return salt.Substring(0, salt.LastIndexOf('$') + 1) + Convert.ToBase64String(hash_data);
        }

        public bool Verify(string password, string hash)
        {
            return hash == HashPassword(password, hash);
        }

        #endregion
        #region IKeyDerivationFunction Members

        public byte[] DeriveKey(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes)
        {
            return kdf.DeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        #endregion
    }
}
