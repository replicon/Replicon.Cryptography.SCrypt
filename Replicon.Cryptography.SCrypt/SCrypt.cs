using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Security.Permissions;

namespace Replicon.Cryptography.SCrypt
{
    /// <summary>A .NET wrapper for a native implementation of the scrypt key-derivation function.  In addition to
    /// exposing the raw key-derivation function (DerivePassword), SCrypt also contains helper functions for a common
    /// use-case of scrypt as a password hashing algorithm.</summary>
    public static class SCrypt
    {
        #region mixed-mode assembly loader

        /*
         * Upon attempting to perform any SCrypt operations, we hook into the AppDomain's AssemblyResolve event to
         * provide a custom resolver for the Replicon.Cryptography.SCrypt.MMA assembly.  When asked to resolve it, we
         * determine whether we should be using the 32-bit or 64-bit version, extract the correct one from an embedded
         * resource to a temp directory, and then load it from the temp directory.
         */

        private static object hookupLock = new object();
        private static bool hookupComplete = false;
        private static string tempPath = null;

        private static void HookupAssemblyLoader()
        {
            if (hookupComplete)
                return;

            lock (hookupLock)
            {
                if (hookupComplete)
                    return;

                AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);
                AppDomain.CurrentDomain.DomainUnload += new EventHandler(CurrentDomain_ProcessExit);
                AppDomain.CurrentDomain.ProcessExit += new EventHandler(CurrentDomain_ProcessExit);

                hookupComplete = true;
            }
        }

        private static void CurrentDomain_ProcessExit(object sender, EventArgs e)
        {
            if (tempPath != null)
            {
                try
                {
                    Directory.Delete(tempPath, true);
                    tempPath = null;
                }
                catch
                {
                }
            }
        }

        /// <summary>
        /// There is a similar method in the .NET 4 base classes, but we need to implement our own to support .NET
        /// 3.5 still.
        /// </summary>
        private static void CopyStream(Stream input, Stream output)
        {
            byte[] buffer = new byte[16 * 1024];
            while (true)
            {
                int read = input.Read(buffer, 0, buffer.Length);
                if (read == 0)
                    break;
                output.Write(buffer, 0, read);
            }
        }

        private static Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            if (args.Name.StartsWith("Replicon.Cryptography.SCrypt.MMA,"))
            {
                lock (hookupLock)
                {
                    if (tempPath == null)
                    {
                        string root = Path.GetTempPath();
                        tempPath = Path.Combine(root, Path.GetRandomFileName());
                        Directory.CreateDirectory(tempPath);

                        string dll;
                        string pdb;

                        if (IntPtr.Size == 8)
                        {
                            dll = "Replicon.Cryptography.SCrypt.Replicon.Cryptography.SCrypt.MMA-x64.dll";
                            pdb = "Replicon.Cryptography.SCrypt.Replicon.Cryptography.SCrypt.MMA-x64.pdb";
                        }
                        else
                        {
                            dll = "Replicon.Cryptography.SCrypt.Replicon.Cryptography.SCrypt.MMA-win32.dll";
                            pdb = "Replicon.Cryptography.SCrypt.Replicon.Cryptography.SCrypt.MMA-win32.pdb";
                        }

                        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(dll))
                        using (Stream output = new FileStream(Path.Combine(tempPath, "Replicon.Cryptography.SCrypt.MMA.dll"), FileMode.CreateNew))
                            CopyStream(input, output);

                        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(pdb))
                        using (Stream output = new FileStream(Path.Combine(tempPath, "Replicon.Cryptography.SCrypt.MMA.pdb"), FileMode.CreateNew))
                            CopyStream(input, output);
                    }

                    return Assembly.LoadFile(Path.Combine(tempPath, "Replicon.Cryptography.SCrypt.MMA.dll"));
                }
            }

            return null;
        }

        /// <summary>
        /// CRT initialization when first accessing the mixed-mode assembly will attempt to initialize a CRT appdomain,
        /// which attempts to copy the current thread's principal.  However, because the new appdomain doesn't have
        /// a configuration matching the current appdomain, it often can't find the assemblies required to deserialize
        /// the principal.  To work around this, we just null-out the thread principal when calling the mixed-mode
        /// assemblies.
        /// </summary>
        private class NullPrincipalBlock : IDisposable
        {
            private bool controllingPrincipal;
            private IPrincipal storedPrincipal;

            public NullPrincipalBlock()
            {
                // Only attempt to control the principal if we have permission to.  If not, then NullPrincipalBlock
                // will have no effect, which will work just fine if either we don't do CRT initialization, or we
                // have a principal that will be deserializable in CRT initialization.
                var controlPrincipalPermission = new SecurityPermission(SecurityPermissionFlag.ControlPrincipal);
                controllingPrincipal = controlPrincipalPermission.IsSubsetOf(null);

                if (controllingPrincipal)
                {
                    this.storedPrincipal = Thread.CurrentPrincipal;
                    Thread.CurrentPrincipal = null;
                }
            }

            public void Dispose()
            {
                if (storedPrincipal != null && controllingPrincipal)
                {
                    Thread.CurrentPrincipal = storedPrincipal;
                    storedPrincipal = null;
                }
            }
        }

        #endregion
        #region Random number generator

        private static RandomNumberGenerator randomGenerator;
        private static object randomGeneratorLock = new object();

        private static RandomNumberGenerator RandomGenerator
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
        #region User interface

        /// <summary>Default value for saltLengthBytes used by parameterless GenerateSalt, currently 16 bytes.</summary>
        public static readonly uint DefaultSaltLengthBytes = 16;

        /// <summary>Default value for N used by parameterless GenerateSalt, currently 2^14.</summary>
        public static readonly ulong Default_N = 16384;

        /// <summary>Default value for r used by parameterless GenerateSalt, currently 8.</summary>
        public static readonly uint Default_r = 8;

        /// <summary>Default value for p used by parameterless GenerateSalt, currently 1.</summary>
        public static readonly uint Default_p = 1;

        /// <summary>Default value for hashLengthBytes used by parameterless GenerateSalt, currently 32 bytes.</summary>
        public static readonly uint DefaultHashLengthBytes = 32;

        /// <summary>Generate a salt for use with HashPassword, selecting reasonable default values for scrypt
        /// parameters that are appropriate for an interactive login verification workflow.</summary>
        /// <remarks>Uses the default values in DefaultSaltLengthBytes, Default_N, Default_r, Default_r, and
        /// DefaultHashLengthBytes.</remarks>
        public static string GenerateSalt()
        {
            return GenerateSalt(DefaultSaltLengthBytes, Default_N, Default_r, Default_p, DefaultHashLengthBytes);
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

        /// <summary>Generate a password hash using a newly generated salt, with default salt parameters.</summary>
        /// <param name="password">A password to hash.</param>
        public static string HashPassword(string password)
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
            var error = InternalTryParseSalt(salt, out saltBytes, out N, out r, out p, out hashLengthBytes);
            return error == null;
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
            var error = InternalTryParseSalt(salt, out saltBytes, out N, out r, out p, out hashLengthBytes);
            if (error != null)
                throw error;
        }

        /// <summary>Generate a password hash using a specific password salt.</summary>
        /// <param name="password">A password to hash.</param>
        /// <param name="salt">Salt to hash the password with.  This is often a password hash from a previous
        /// HashPassword call, which contains the salt of the original password call; in that case, the returned
        /// hash will be identical to the salt parameter if the password is the same password as the original.</param>
        public static string HashPassword(string password, string salt)
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

        /// <summary>Verify that a given password matches a given hash.</summary>
        public static bool Verify(string password, string hash)
        {
            return hash == HashPassword(password, hash);
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
            HookupAssemblyLoader();
            using (new NullPrincipalBlock())
                return WrappedDeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        #endregion
        #region Wrapped methods

        /*
         * Our exposed methods can't have a direct Replicon.Cryptography.SCrypt.MMA reference in them, since they need to hookup the fancy
         * assembly resolver before it's referenced.  Hence we have these wrapped methods that look pointless.
         */

        private static Byte[] WrappedDeriveKey(Byte[] password, Byte[] salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes)
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.DeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        #endregion
    }
}
