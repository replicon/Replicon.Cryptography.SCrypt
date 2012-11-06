using System;
using System.IO;
using System.Reflection;

namespace SCrypt
{
    public class SCrypt
    {
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
            if (args.Name.StartsWith("scrypt-mma,"))
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
                            dll = "scrypt.scrypt-mma-x64.dll";
                            pdb = "scrypt.scrypt-mma-x64.pdb";
                        }
                        else
                        {
                            dll = "scrypt.scrypt-mma-win32.dll";
                            pdb = "scrypt.scrypt-mma-win32.pdb";
                        }

                        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(dll))
                        using (Stream output = new FileStream(Path.Combine(tempPath, "scrypt-mma.dll"), FileMode.CreateNew))
                            CopyStream(input, output);

                        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(pdb))
                        using (Stream output = new FileStream(Path.Combine(tempPath, "scrypt-mma.pdb"), FileMode.CreateNew))
                            CopyStream(input, output);
                    }

                    return Assembly.LoadFile(Path.Combine(tempPath, "scrypt-mma.dll"));
                }
            }

            return null;
        }

        public static String GenerateSalt()
        {
            HookupAssemblyLoader();
            return WrappedGenerateSalt();
        }

        public static String GenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p, UInt32 hashLengthBytes)
        {
            HookupAssemblyLoader();
            return WrappedGenerateSalt(saltLengthBytes, N, r, p, hashLengthBytes);
        }

        public static String HashPassword(String password)
        {
            HookupAssemblyLoader();
            return WrappedHashPassword(password);
        }

        public static String HashPassword(String password, String salt)
        {
            HookupAssemblyLoader();
            return WrappedHashPassword(password, salt);
        }

        public static bool Verify(String password, String hash)
        {
            HookupAssemblyLoader();
            return WrappedVerify(password, hash);
        }

        public static Byte[] DeriveKey(Byte[] password, Byte[] salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes)
        {
            HookupAssemblyLoader();
            return WrappedDeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        private static String WrappedGenerateSalt()
        {
            return SCryptMMA.SCrypt.GenerateSalt();
        }

        private static String WrappedGenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p, UInt32 hashLengthBytes)
        {
            return SCryptMMA.SCrypt.GenerateSalt(saltLengthBytes, N, r, p, hashLengthBytes);
        }

        private static String WrappedHashPassword(String password)
        {
            return SCryptMMA.SCrypt.HashPassword(password);
        }

        private static String WrappedHashPassword(String password, String salt)
        {
            return SCryptMMA.SCrypt.HashPassword(password, salt);
        }

        private static bool WrappedVerify(String password, String hash)
        {
            return SCryptMMA.SCrypt.Verify(password, hash);
        }

        private static Byte[] WrappedDeriveKey(Byte[] password, Byte[] salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes)
        {
            return SCryptMMA.SCrypt.DeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }
    }
}
