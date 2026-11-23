using System.Runtime.InteropServices;

namespace MiniJail;

/// <summary>Układ identyczny z `struct rlimit` (rlim_cur, rlim_max) poprzedzony numerem zasobu.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct Limit
{
    public int Resource;
    public ulong Cur;
    public ulong Max;
}

/// <summary>
/// Cienka warstwa P/Invoke na libc (Linux x86_64 oraz ARM64).
/// Wszystkie typy są blittable — część tych wywołań robimy w dziecku
/// zaraz po fork(), gdzie nie wolno nam alokować pamięci zarządzanej.
/// </summary>
internal static unsafe class Native
{
    const string Libc = "libc";

    public const int SIGTRAP = 5, SIGKILL = 9, SIGSEGV = 11, SIGXCPU = 24, SIGXFSZ = 25;

    // ptrace
    public const int PTRACE_TRACEME = 0;
    public const int PTRACE_SYSCALL = 24;
    public const int PTRACE_SETOPTIONS = 0x4200;
    public const int PTRACE_GET_SYSCALL_INFO = 0x420e; // Linux >= 5.3
    public const long PTRACE_O_TRACESYSGOOD = 1;       // stop na syscallu = SIGTRAP | 0x80
    public const long PTRACE_O_EXITKILL = 1L << 20;    // śmierć supervisora zabija dziecko

    // setrlimit
    public const int RLIMIT_CPU = 0, RLIMIT_FSIZE = 1, RLIMIT_CORE = 4, RLIMIT_NOFILE = 7, RLIMIT_AS = 9;

    // open
    public const int O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0x40, O_TRUNC = 0x200;

    // wait4
    public const int __WALL = 0x40000000;

    [DllImport(Libc)] public static extern int fork();
    [DllImport(Libc)] public static extern long ptrace(int request, int pid, nint addr, nint data);
    [DllImport(Libc)] public static extern int wait4(int pid, int* status, int options, byte* rusage);
    [DllImport(Libc)] public static extern int kill(int pid, int sig);
    [DllImport(Libc)] public static extern int execve(nint path, nint* argv, nint* envp);
    [DllImport(Libc)] public static extern void _exit(int code);
    [DllImport(Libc)] public static extern int setrlimit(int resource, ulong* rlim);
    [DllImport(Libc)] public static extern int dup2(int oldfd, int newfd);
    [DllImport(Libc)] public static extern int open(nint path, int flags, int mode);
    [DllImport(Libc)] public static extern int close(int fd);
    [DllImport(Libc)] public static extern int close_range(uint first, uint last, int flags);

    // Makra z <sys/wait.h>
    public static bool WIFEXITED(int s) => (s & 0x7f) == 0;
    public static int WEXITSTATUS(int s) => (s >> 8) & 0xff;
    public static bool WIFSIGNALED(int s) => ((s & 0x7f) + 1) >> 1 > 0 && (s & 0x7f) != 0x7f;
    public static int WTERMSIG(int s) => s & 0x7f;
    public static bool WIFSTOPPED(int s) => (s & 0xff) == 0x7f;
    public static int WSTOPSIG(int s) => (s >> 8) & 0xff;
}