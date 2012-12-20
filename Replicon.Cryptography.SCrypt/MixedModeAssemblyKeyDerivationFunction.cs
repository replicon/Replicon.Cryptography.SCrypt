using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;

namespace Replicon.Cryptography.SCrypt
{
    class MixedModeAssemblyKeyDerivationFunction : IKeyDerivationFunction
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
        private static bool expensiveCrtInitialization = false;

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

        private static void EnsureCrtInitialized()
        {
            if (!expensiveCrtInitialization)
            {
                EscapeExecutionContext(() => { Replicon.Cryptography.SCrypt.MMA.SCrypt.ExpensiveCrtInitialization(); return false; });
                expensiveCrtInitialization = true;
            }
        }

        private static void SafeSetPrincipal(IPrincipal principal)
        {
            // We really need to null out the principal in order to guarentee CRT initialization will work.
            // It seems safe to assert the ControlPrincipal permission here because of the limited scope that
            // this block will operate under, where all it can do is run the SCrypt library.
            var controlPrincipalPermission = new SecurityPermission(SecurityPermissionFlag.ControlPrincipal);
            controlPrincipalPermission.Assert();
            Thread.CurrentPrincipal = principal;
        }

        /// <summary>
        /// CRT initialization when first accessing the mixed-mode assembly will attempt to initialize a CRT appdomain,
        /// which attempts to copy the current thread's execution context.  However, because the new appdomain doesn't
        /// have a configuration matching the current appdomain, it often can't find the assemblies required to
        /// deserialize the principal, or other objects stored in the execution context.  To work around this, we
        /// attempt to "escape" our execution context by spawning a new thread.  I welcome ideas for how to make this
        /// more efficient.
        /// </summary>
        private static T EscapeExecutionContext<T>(Func<T> callback)
        {
            var suppressExecutionContextFlow = ExecutionContext.SuppressFlow();
            try
            {
                T retval = default(T);
                Exception threadException = null;
                var thread = new Thread(() =>
                {
                    try
                    {
                        try
                        {
                            SafeSetPrincipal(null);
                            retval = callback();
                        }
                        catch (Exception e)
                        {
                            threadException = e;
                        }
                    }
                    catch
                    {
                        // Prevent unhandled exceptions from exiting thread under any circumstances, to ensure that
                        // process crashes cannot occur.
                    }
                });
                thread.Start();
                thread.Join();
                if (threadException != null)
                    throw new TargetInvocationException(threadException);
                return retval;
            }
            finally
            {
                suppressExecutionContextFlow.Undo();
            }
        }

        #endregion
        #region IKeyDerivationFunction Members

        public byte[] DeriveKey(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes)
        {
            HookupAssemblyLoader();
            EnsureCrtInitialized();
            return WrappedDeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        // Ensure the CLR does not inline this method; doing so would prevent HookupAssemblyLoader from occuring
        // before the MMA assembly reference needs to be evaluated.
        [MethodImpl(MethodImplOptions.NoInlining)]
        private byte[] WrappedDeriveKey(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes)
        {
            return Replicon.Cryptography.SCrypt.MMA.SCrypt.DeriveKey(password, salt, N, r, p, derivedKeyLengthBytes);
        }

        #endregion
    }
}
