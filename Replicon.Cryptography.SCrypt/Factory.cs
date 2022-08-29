
namespace Replicon.Cryptography.SCrypt
{
    /// <summary>
    /// Factory for creating pre-defined implementations of IPasswordHash and IKeyDerivationFunction.
    /// </summary>
    public static class Factory
    {
        #region IPasswordHash factory

        private static IPasswordHash bestPasswordHash;
        private static readonly object passwordHashCreationLock = new object();

        /// <summary>
        /// Create an IPasswordHash implementation, using the best available key-derivation function implementation.
        /// </summary>
        public static IPasswordHash CreatePasswordHash()
        {
            if (bestPasswordHash != null)
                return bestPasswordHash;

            lock (passwordHashCreationLock)
            {
                if (bestPasswordHash != null)
                    return bestPasswordHash;

                return bestPasswordHash = new DefaultPasswordHash(CreateKeyDerivationFunction());
            }
        }

        /// <summary>
        /// Create an IPasswordHash implementation, using the provided key-derivation function implementation.
        /// </summary>
        public static IPasswordHash CreatePasswordHash(IKeyDerivationFunction kdf)
        {
            return new DefaultPasswordHash(kdf);
        }

        #endregion
        #region IKeyDerivationFunction factory

        private static IKeyDerivationFunction Kdf;
        private static readonly object kdfCreationLock = new object();

        /// <summary>
        /// Create an IKeyDerivationFunction representing the best available key-derivation function implementation.
        /// </summary>
        public static IKeyDerivationFunction CreateKeyDerivationFunction()
        {
            return CreateSCryptKeyDerivationFunction();
        }

        /// <summary>
        /// Create an IKeyDerivationFunction. 
        /// </summary>
        public static IKeyDerivationFunction CreateSCryptKeyDerivationFunction()
        {
            if (Kdf != null)
                return Kdf;

            lock (kdfCreationLock)
            {
                if (Kdf != null)
                    return Kdf;

                return Kdf = new KeyDerivationFunction();
            }
        }

        #endregion
    }
}
