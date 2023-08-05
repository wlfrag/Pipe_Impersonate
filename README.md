# Pipe_Impersonate


1. Requires SpoolSample.exe
2. Requires Account with SeImpersonatePrivileges.
3. Only works with interactiveLogon. (No IIS service accounts etc.)

Creates a named pipe from arguments in the command line.
Calls impersonateNamedPipeClient on the pipe handle we created.
Waits for connections to the named pipe.

Once a client connects (and we have SeImpersonatePrivilege), calls OpenThreadToken to get token handle. 
We will then call DuplicateTokenEx to get a usable token handle which we can call CreateProcessWithTokenW

Used in conjunction with Spoolsample.exe 

## Usage


![image](https://github.com/wlfrag/Pipe_Impersonate/assets/43529877/2ed60d01-d215-4be4-983e-0148c0553981)


Make sure user has SeImpersonatePrivilege.


C:\Users\test\source\repos\Pipe_Impersonate\Pipe_Impersonate\bin\x64\Release\Pipe_Impersonate.exe \\.\pipe\test1\pipe\spoolss


Edit the code to use it to start whichever payload we desire.



![image](https://github.com/wlfrag/Pipe_Impersonate/assets/43529877/96f44d5b-7353-4fd9-bb9d-f80ec6a5a2f2)




![image](https://github.com/wlfrag/Pipe_Impersonate/assets/43529877/2cec81d6-dc4a-404b-bacf-50ec5dfc7636)



