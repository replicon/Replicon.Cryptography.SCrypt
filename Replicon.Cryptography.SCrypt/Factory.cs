using System;

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

        private static IKeyDerivationFunction nativeKdf;
        private static readonly object kdfCreationLock = new object();

        /// <summary>
        /// Create an IKeyDerivationFunction representing the best available key-derivation function implementation.
        /// </summary>
        public static IKeyDerivationFunction CreateKeyDerivationFunction()
        {
            return CreateNativeKeyDerivationFunction();
        }

        /// <summary>
        /// Create an IKeyDerivationFunction implemented by a mixed-mode assembly.  This is a high-performance
        /// implementation using SSE2, but requires support for C++/CLI mixed-mode assemblies (ie. doesn't work on
        /// Mono), and requires that the current environment be supported (.NET 3.5 or 4.0, x86 or x64).
        /// </summary>
        /// <remarks>If the mixed-mode assembly cannot be loaded, this method will... FIXME: what?</remarks>
        public static IKeyDerivationFunction CreateNativeKeyDerivationFunction()
        {
            if (nativeKdf != null)
                return nativeKdf;

            lock (kdfCreationLock)
            {
                if (nativeKdf != null)
                    return nativeKdf;

                return nativeKdf = new MixedModeAssemblyKeyDerivationFunction();
            }
        }

        #endregion
    }
}
