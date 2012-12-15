using System;

namespace Replicon.Cryptography.SCrypt
{
    /// <summary>
    /// Interface wrapping an scrypt key-derivation function implementation.
    /// </summary>
    public interface IKeyDerivationFunction
    {
        /// <summary>Key-derivation function.</summary>
        /// <param name="password">The password bytes to generate the key based upon.</param>
        /// <param name="salt">Random salt bytes to make the derived key unique.</param>
        /// <param name="N">CPU/memory cost parameter.  Must be a value 2^N.  2^14 (16384) causes a calculation time
        /// of approximately 50-70ms on 2010 era hardware; each successive value (eg. 2^15, 2^16, ...) should
        /// double the amount of CPU time and memory required.</param>
        /// <param name="r">scrypt 'r' tuning parameter</param>
        /// <param name="p">scrypt 'p' tuning parameter (parallelization parameter); a large value of p can increase
        /// computational cost of scrypt without increasing the memory usage.</param>
        /// <param name="derivedKeyLengthBytes">The number of bytes of key to derive.</param>
        byte[] DeriveKey(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes);
    }
}
