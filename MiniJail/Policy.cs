using System.Runtime.InteropServices;
using System.Text;

namespace MiniJail;

/// <summary>
/// Polityka bezpieczeństwa: biała lista syscalli + weryfikacja argumentów (deskryptorów, ścieżek, flag).
/// Obsługuje zarówno ARM64 (Apple Silicon Docker), jak i x86_64.
/// </summary>
internal sealed class Policy
{
    const uint AUDIT_ARCH_X86_64  = 0xC000003E;
    const uint AUDIT_ARCH_AARCH64 = 0xC00000B7; // opcja dla Mac XD

    const int O_ACCMODE = 3, O_CREAT = 0x40, O_TRUNC = 0x200, O_TMPFILE = 0x410000;

    static readonly uint ExpectedArch = RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64   => AUDIT_ARCH_X86_64,
        Architecture.Arm64 => AUDIT_ARCH_AARCH64,
        _ => throw new PlatformNotSupportedException()
    };

    static readonly Dictionary<ulong, string> Names =
        RuntimeInformation.ProcessArchitecture == Architecture.Arm64
        ? new() // ARM64 (linux/include/uapi/asm-generic/unistd.h)
        {
            [29] = "ioctl", [35] = "unlinkat", [48] = "faccessat", [56] = "openat", [57] = "close",
            [61] = "getdents64", [62] = "lseek", [63] = "read", [64] = "write", [65] = "readv",
            [66] = "writev", [67] = "pread64", [68] = "pwrite64", [78] = "readlinkat",
            [79] = "newfstatat", [80] = "fstat", [93] = "exit", [94] = "exit_group",
            [96] = "set_tid_address", [98] = "futex", [99] = "set_robust_list",
            [101] = "nanosleep", [113] = "clock_gettime", [115] = "clock_nanosleep",
            [124] = "sched_yield", [129] = "kill", [130] = "tkill", [131] = "tgkill",
            [134] = "rt_sigaction", [135] = "rt_sigprocmask", [139] = "rt_sigreturn",
            [160] = "uname", [172] = "getpid", [174] = "getuid", [198] = "socket",
            [203] = "connect", [214] = "brk", [215] = "munmap", [216] = "mremap",
            [220] = "clone", [221] = "execve", [222] = "mmap", [226] = "mprotect",
            [233] = "madvise", [260] = "wait4", [261] = "prlimit64", [278] = "getrandom",
            [291] = "statx", [293] = "rseq", [435] = "clone3", [436] = "close_range",
        }
        : new() // x86_64
        {
            [0] = "read", [1] = "write", [2] = "open", [3] = "close", [4] = "stat", [5] = "fstat", [6] = "lstat",
            [8] = "lseek", [9] = "mmap", [10] = "mprotect", [11] = "munmap", [12] = "brk",
            [13] = "rt_sigaction", [14] = "rt_sigprocmask", [15] = "rt_sigreturn", [16] = "ioctl",
            [17] = "pread64", [18] = "pwrite64", [19] = "readv", [20] = "writev", [21] = "access",
            [22] = "pipe", [24] = "sched_yield", [25] = "mremap", [28] = "madvise",
            [32] = "dup", [33] = "dup2", [35] = "nanosleep", [39] = "getpid",
            [41] = "socket", [42] = "connect", [43] = "accept", [44] = "sendto", [45] = "recvfrom",
            [56] = "clone", [57] = "fork", [58] = "vfork", [59] = "execve", [60] = "exit",
            [61] = "wait4", [62] = "kill", [63] = "uname", [72] = "fcntl", [79] = "getcwd", [80] = "chdir",
            [82] = "rename", [83] = "mkdir", [84] = "rmdir", [85] = "creat", [87] = "unlink",
            [89] = "readlink", [90] = "chmod", [96] = "gettimeofday", [97] = "getrlimit", [101] = "ptrace",
            [102] = "getuid", [105] = "setuid", [157] = "prctl", [158] = "arch_prctl", [165] = "mount",
            [200] = "tkill", [201] = "time", [202] = "futex", [204] = "sched_getaffinity",
            [217] = "getdents64", [218] = "set_tid_address", [228] = "clock_gettime", [229] = "clock_getres",
            [230] = "clock_nanosleep", [231] = "exit_group", [234] = "tgkill", [257] = "openat",
            [262] = "newfstatat", [267] = "readlinkat", [273] = "set_robust_list", [302] = "prlimit64",
            [318] = "getrandom", [332] = "statx", [334] = "rseq", [435] = "clone3", [436] = "close_range",
        };

    // Minimum potrzebne statycznie zlinkowanemu programowi w C/C++ (start libc, malloc, printf, scanf).
    static readonly HashSet<string> Allowed = new()
    {
        "read", "write", "writev", "close", "fstat", "newfstatat", "statx", "lseek",
        "mmap", "munmap", "mprotect", "mremap", "brk", "madvise",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "arch_prctl", "set_tid_address", "set_robust_list", "rseq", "prlimit64",
        "getrandom", "readlink", "readlinkat", "uname", "ioctl", "futex",
        "clock_gettime", "nanosleep", "clock_nanosleep", "sched_yield",
        "exit", "exit_group",
        "openat", // dopuszczone warunkowo — sprawdzamy ścieżkę i flagi w CheckOpenat
    };

    readonly HashSet<string> _readableFiles;

    public Policy(IEnumerable<string>? readableFiles) =>
        _readableFiles = new HashSet<string>(readableFiles ?? Array.Empty<string>());

    public static string NameOf(ulong nr) => Names.TryGetValue(nr, out var n) ? n : $"syscall_{nr}";

    /// <returns>null = wolno; w przeciwnym razie powód odmowy.</returns>
    public string? Check(int pid, uint arch, ulong nr, ReadOnlySpan<ulong> a)
    {
        if (arch != ExpectedArch)
            return $"nieoczekiwana architektura syscalli (0x{arch:x})";

        var name = NameOf(nr);

        if (!Allowed.Contains(name))
            return $"zabroniony syscall {name} ({nr})";

        switch (name)
        {
            case "write":
            case "writev":
                if (a[0] != 1 && a[0] != 2)
                    return $"{name} do deskryptora {a[0]} (wolno tylko stdout=1 i stderr=2)";
                break;

            case "ioctl":
                if (a[1] != 0x5401) // TCGETS — libc używa tego przy isatty()
                    return $"ioctl z komendą 0x{a[1]:x}";
                break;

            case "prlimit64":
                if (a[2] != 0) // new_limit != NULL -> próba zmiany limitów
                    return "prlimit64 próbuje zmienić limity";
                break;

            case "openat":
                return CheckOpenat(pid, a);
        }
        return null;
    }

    string? CheckOpenat(int pid, ReadOnlySpan<ulong> a)
    {
        // openat(dirfd, pathname, flags, mode)
        int flags = (int)a[2];
        if ((flags & O_ACCMODE) != 0) return "openat do zapisu";
        if ((flags & (O_CREAT | O_TRUNC)) != 0) return "openat z O_CREAT/O_TRUNC";
        if ((flags & O_TMPFILE) == O_TMPFILE) return "openat z O_TMPFILE";

        var path = ReadCString(pid, a[1]);
        if (path is null) return "openat: nie da się odczytać ścieżki z pamięci procesu";
        if (!path.StartsWith('/')) return $"openat: ścieżka względna \"{path}\"";
        if (!_readableFiles.Contains(path)) return $"openat(\"{path}\") — plik spoza listy dozwolonych";
        return null;
    }

    static string? ReadCString(int pid, ulong addr)
    {
        try
        {
            using var fs = new FileStream($"/proc/{pid}/mem", FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite, bufferSize: 1);
            var bytes = new List<byte>();
            var buf = new byte[256];
            while (bytes.Count < 4096)
            {
                int chunk = (int)Math.Min((ulong)buf.Length, 4096 - (addr % 4096));
                fs.Seek((long)addr, SeekOrigin.Begin);
                int n = fs.Read(buf, 0, chunk);
                if (n <= 0) return null;
                for (int i = 0; i < n; i++)
                {
                    if (buf[i] == 0) return Encoding.UTF8.GetString(bytes.ToArray());
                    bytes.Add(buf[i]);
                }
                addr += (ulong)n;
            }
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}