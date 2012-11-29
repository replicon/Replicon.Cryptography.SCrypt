using System;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Threading;

namespace Replicon.Cryptography.SCrypt
{
    public class SCrypt
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

        #endregion

        /// <summary>
        /// CRT initialization when first accessing the mixed-mode assembly will attempt to initialize a CRT appdomain,
        /// which attempts to copy the current thread's principal.  However, because the new appdomain doesn't have
        /// a configuration matching the current appdomain, it often can't find the assemblies required to deserialize
        /// the principal.  To work around this, we just null-out the thread principal when calling the mixed-mode
        /// assemblies.
        /// </summary>
        private class NullPrincipalBlock : IDisposable
        {
            private IPrincipal storedPrincipal;

            public NullPrincipalBlock()
            {
                this.storedPrincipal = Thread.CurrentPrincipal;
                Thread.CurrentPrincipal = null;
            }

            public void Dispose()
            {
                if (this.storedPrincipal != null)
                {
                    Thread.CurrentPrincipal = this.storedPrincipal;
                    this.storedPrincipal = null;
                }
            }
        }

        #region Exposed methods

        public static UInt32 DefaultSaltLengthBytes
        {
            get
            {
                HookupAssemblyLoader();
                using (new NullPrincipalBlock())
                    return WrappedDefaultSaltLengthBytes;
            }
        }

        public static UInt64 Default_N
        {
            get
            {
                HookupAssemblyLoader();
                using (new NullPrincipalBlock())
                    return WrappedDefault_N;
            }
        }

        public static UInt32 Default_r
        {
            get
            {
                HookupAssemblyLoader();
                using (new NullPrincipalBlock())
                    return WrappedDefault_r;
            }
        }

        public static UInt32 Default_p
        {
            get
            {
                HookupAssemblyLoader();
                using (new NullPrincipalBlock())
                    return WrappedDefault_p;
            }
        }

        public static UInt32 DefaultHashLengthBytes
        {
            get
            {
                HookupAssemblyLoader();
                using (new NullPrincipalBlock())
                    return WrappedDefaultHashLengthBytes;
            }
        }

        public static String GenerateSalt()
        {
            HookupAssemblyLoader();
            using (new NullPrincipalBlock())
                return WrappedGenerateSalt();
        }

        public static String GenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p, UInt32 hashLengthBytes)
        {
            HookupAssemblyLoader();
            using (new NullPrincipalBlock())
                return WrappedGenerateSalt(saltLengthBytes, N, r, p, hashLengthBytes);
        }

        public static String HashPassword(String password)
        {
            HookupAssemblyLoader();
            using (new NullPrincipalBlock())
                return WrappedHashPassword(password);
        }

        public static String HashPassword(String password, String salt)
        {
            HookupAssemblyLoader();
            using (new NullPrincipalBlock())
                return WrappedHashPassword(password, salt);
        }

        public static bool Verify(String password, String hash)
        {
            HookupAssemblyLoader();
            using (new NullPrincipalBlock())
                return WrappedVerify(password, hash);
        }

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

        private static UInt32 WrappedDefaultSaltLengthBytes
        {
            get { return Replicon.Cryptography.SCrypt.MMA.SCrypt.DefaultSaltLengthBytes; }
        }
        private static UInt64 WrappedDefault_N
        {
            get { return Replicon.Cryptography.SCrypt.MMA.SCrypt.Default_N; }
        }
        private static UInt32 WrappedDefault_r
        {
            get { return Replicon.Cryptography.SCrypt.MMA.SCrypt.Default_r; }
        }
        private static UInt32 WrappedDefault_p
        {
            get { return Replicon.Cryptography.SCrypt.MMA.SCrypt.Default_p; }
        }
        private static UInt32 WrappedDefaultHashLengthBytes
        {
            get { return Replicon.Cryptography.SCrypt.MMA.SCrypt.DefaultHashLengthBytes; }
        }

        private static String WrappedGenerateSalt()
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.GenerateSalt();
        }

        private static String WrappedGenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p, UInt32 hashLengthBytes)
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.GenerateSalt(saltLengthBytes, N, r, p, hashLengthBytes);
        }

        private static String WrappedHashPassword(String password)
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.HashPassword(password);
        }

        private static String WrappedHashPassword(String password, String salt)
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.HashPassword(password, salt);
        }

        private static bool WrappedVerify(String password, String hash)
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.Verify(password, hash);
        }

        private static Byte[] WrappedDeriveKey(Byte[] password, Byte[] salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes)
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.DeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        #endregion
    }
}
