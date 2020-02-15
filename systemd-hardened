security and hardening options for systemd service units

A common and reliable pattern in service unit files is thus:

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectSystem=strict
ProtectHome=read-only
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

But there's so much more you can do. Here are some key option definitions which I've excerpted and abbreviated from systemd's manual pages.

    IPAddressAllow, IPAddressDeny

Turn on address range network traffic filtering for IP packets sent and received over AF_INET and AF_INET6 sockets. Both directives take a space separated list of IPv4 or IPv6 addresses, each optionally suffixed with an address prefix length in bits (separated by a "/" character). If the latter is omitted, the address is considered a host address, i.e. the prefix covers the whole address (32 for IPv4, 128 for IPv6).

    DeviceAllow

Control access to specific device nodes by the executed processes. Takes two space-separated strings: a device node specifier followed by a combination of r, w, m to control reading, writing, or creation of the specific device node(s) by the unit (mknod), respectively.

    DevicePolicy

Control the policy for allowing device access:

strict means to only allow types of access that are explicitly specified.

closed in addition, allows access to standard pseudo devices including /dev/null, /dev/zero, /dev/full, /dev/random, and /dev/urandom.

auto in addition, allows access to all devices if no explicit DeviceAllow= is present. This is the default.

    ConditionSecurity

May be used to check whether the given security technology is enabled on the system. Currently, the recognized values are selinux, apparmor, tomoyo, ima, smack, audit and uefi-secureboot. The test may be negated by prepending an exclamation mark.

    CapabilityBoundingSet

Controls which capabilities to include in the capability bounding set for the executed process. See capabilities(7) for details. Takes a whitespace-separated list of capability names, e.g. CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_SYS_PTRACE.

    MemoryDenyWriteExecute

Takes a boolean argument. If set, attempts to create memory mappings that are writable and executable at the same time, or to change existing memory mappings to become executable, or mapping shared memory segments as executable are prohibited. Specifically, a system call filter is added that rejects mmap system calls with both PROT_EXEC and PROT_WRITE set, mprotect or pkey_mprotect system calls with PROT_EXEC set and shmat system calls with SHM_EXEC set. Note that this option is incompatible with programs and libraries that generate program code dynamically at runtime, including JIT execution engines, executable stacks, and code "trampoline" feature of various C compilers. This option improves service security, as it makes harder for software exploits to change running code dynamically. However, the protection can be circumvented, if the service can write to a filesystem, which is not mounted with noexec (such as /dev/shm), or it can use memfd_create(). This can be prevented by making such file systems inaccessible to the service (e.g. InaccessiblePaths=/dev/shm) and installing further system call filters (SystemCallFilter=~memfd_create).

    NoNewPrivileges

Takes a boolean argument. If true, ensures that the service process and all its children can never gain new privileges through execve() (e.g. via setuid or setgid bits, or filesystem capabilities). This is the simplest and most effective way to ensure that a process and its children can never elevate privileges again. Defaults to false, but certain settings override this and ignore the value of this setting. This is the case when SystemCallFilter=, SystemCallArchitectures=, RestrictAddressFamilies=, RestrictNamespaces=, PrivateDevices=, ProtectKernelTunables=, ProtectKernelModules=, MemoryDenyWriteExecute=, RestrictRealtime=, RestrictSUIDSGID=, DynamicUser= or LockPersonality= are specified. Note that even if this setting is overridden by them, systemctl show shows the original value of this setting. See also: No New Privileges Flag.

    PrivateDevices

Takes a boolean argument. If true, sets up a new /dev mount for the executed processes and only adds API pseudo devices such as /dev/null, /dev/zero or /dev/random (as well as the pseudo TTY subsystem) to it, but no physical devices such as /dev/sda, system memory /dev/mem, system ports /dev/port and others. This is useful to securely turn off physical device access by the executed process. Defaults to false.

    PrivateTmp

Takes a boolean argument. If true, sets up a new file system namespace for the executed processes and mounts private /tmp and /var/tmp directories inside it that is not shared by processes outside of the namespace. This is useful to secure access to temporary files of the process, but makes sharing between processes via /tmp or /var/tmp impossible. If this is enabled, all temporary files created by a service in these directories will be removed after the service is stopped. Defaults to false.

    PrivateUsers

Takes a boolean argument. If true, sets up a new user namespace for the executed processes and configures a minimal user and group mapping, that maps the "root" user and group as well as the unit's own user and group to themselves and everything else to the "nobody" user and group. This is useful to securely detach the user and group databases used by the unit from the rest of the system, and thus to create an effective sandbox environment. All files, directories, processes, IPC objects and other resources owned by users/groups not equaling "root" or the unit's own will stay visible from within the unit but appear owned by the "nobody" user and group. If this mode is enabled, all unit processes are run without privileges in the host user namespace (regardless if the unit's own user/group is "root" or not). Specifically this means that the process will have zero process capabilities on the host's user namespace, but full capabilities within the service's user namespace. Settings such as CapabilityBoundingSet= will affect only the latter, and there's no way to acquire additional capabilities in the host's user namespace. Defaults to off.

    ProtectControlGroups

Takes a boolean argument. If true, the Linux Control Groups (cgroups) hierarchies accessible through /sys/fs/cgroup will be made read-only to all processes of the unit. Except for container managers no services should require write access to the control groups hierarchies; it is hence recommended to turn this on for most services. Defaults to off.

    ProtectHome

Takes a boolean argument or "read-only". If true, the directories /home, /root and /run/user are made inaccessible and empty for processes invoked by this unit. If set to "read-only", the three directories are made read-only instead. It is recommended to enable this setting for all long-running services (in particular network-facing ones), to ensure they cannot get access to private user data, unless the services actually require access to the user's private data. This setting is implied if DynamicUser= is set.

    ProtectKernelModules

Takes a boolean argument. If true, explicit module loading will be denied. This allows to turn off module load and unload operations on modular kernels. It is recommended to turn this on for most services that do not need special file systems or extra kernel modules to work. Default to off. Enabling this option removes CAP_SYS_MODULE from the capability bounding set for the unit, and installs a system call filter to block module system calls, also /usr/lib/modules is made inaccessible. For this setting the same restrictions regarding mount propagation and privileges apply as for ReadOnlyPaths= and related calls, see above. Note that limited automatic module loading due to user configuration or kernel mapping tables might still happen as side effect of requested user operations, both privileged and unprivileged. To disable module auto-load feature please see sysctl.d kernel.modules_disabled mechanism and /proc/sys/kernel/modules_disabled documentation.

    ProtectKernelTunables

Takes a boolean argument. If true, kernel variables accessible through /proc/sys, /sys, /proc/sysrq-trigger, /proc/latency_stats, /proc/acpi, /proc/timer_stats, /proc/fs and /proc/irq will be made read-only to all processes of the unit. Usually, tunable kernel variables should only be written at boot-time, with the sysctl.d mechanism. Almost no services need to write to these at runtime; it is hence recommended to turn this on for most services. For this setting the same restrictions regarding mount propagation and privileges apply as for ReadOnlyPaths= and related calls, see above. Defaults to off. Note that this option does not prevent kernel tuning through IPC interfaces and external programs. However InaccessiblePaths= can be used to make some IPC file system objects inaccessible.

    ProtectKernelLogs

Takes a boolean argument. If true, access to the kernel log ring buffer will be denied. It is recommended to turn this on for most services that do not need to read from or write to the kernel log ring buffer. Enabling this option removes CAP_SYSLOG from the capability bounding set for this unit, and installs a system call filter to block the syslog(2) system call (not to be confused with the libc API syslog(3) for userspace logging). The kernel exposes its log buffer to userspace via /dev/kmsg and /proc/kmsg. If enabled, these are made inaccessible to all the processes in the unit.

This option is only available for system services and is not supported for services running in per-user instances of the service manager.

    ProtectSystem

Takes a boolean argument or the special values "full" or "strict". If true, mounts the /usr and /boot directories read-only for processes invoked by this unit. If set to "full", the /etc directory is mounted read-only, too. If set to "strict" the entire file system hierarchy is mounted read-only, except for the API file system subtrees /dev, proc and /sys (protect these directories using PrivateDevices=, ProtectKernelTunables=, ProtectControlGroups=). This setting ensures that any modification of the vendor-supplied operating system (and optionally its configuration, and local mounts) is prohibited for the service. It is recommended to enable this setting for all long-running services, unless they are involved with system updates or need to modify the operating system in other ways. If this option is used, ReadWritePaths= may be used to exclude specific directories from being made read-only. This setting is implied if DynamicUser= is set. Defaults to off.

    ReadWritePaths, ReadOnlyPaths, InaccessiblePaths

Sets up a new file system namespace for executed processes. These options may be used to limit access a process might have to the file system hierarchy. Each setting takes a space-separated list of paths relative to the host's root directory (i.e. the system running the service manager). Note that if paths contain symlinks, they are resolved relative to the root directory.

Paths listed in ReadWritePaths= are accessible from within the namespace with the same access modes as from outside of it.

Paths listed in ReadOnlyPaths= are accessible for reading only, writing will be refused even if the usual file access controls would permit this.

Paths listed in InaccessiblePaths= will be made inaccessible for processes inside the namespace along with everything below them in the file system hierarchy.

    RestrictAddressFamilies

Restricts the set of socket address families accessible to the processes of this unit. Takes a space-separated list of address family names to whitelist, such as AF_UNIX, AF_INET or AF_INET6. When prefixed with ~ the listed address families will be applied as blacklist, otherwise as whitelist. Note that this restricts access to the socket system call only. Sockets passed into the process by other means (for example, by using socket activation with socket units, see systemd.socket) are unaffected. Also, sockets created with socketpair() (which creates connected AF_UNIX sockets only) are unaffected. Note that this option has no effect on 32-bit x86 and is ignored (but works correctly on x86-64). If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=nobody), NoNewPrivileges=yes is implied. By default, no restriction applies, all address families are accessible to processes. If assigned the empty string, any previous list changes are undone. Use this option to limit exposure of processes to remote systems, in particular via exotic network protocols. Note that in most cases, the local AF_UNIX address family should be included in the configured whitelist as it is frequently used for local communication, including for syslog logging. This does not affect commands prefixed with +.

    RestrictRealtime

Takes a boolean argument. If set, any attempts to enable realtime scheduling in a process of the unit are refused. This restricts access to realtime task scheduling policies such as SCHED_FIFO, SCHED_RR or SCHED_DEADLINE. See sched for details about these scheduling policies. If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied. Realtime scheduling policies may be used to monopolize CPU time for longer periods of time, and may hence be used to lock up or otherwise trigger Denial-of-Service situations on the system. It is hence recommended to restrict access to realtime scheduling to the few programs that actually require them. Defaults to off.

    LockPersonality

Takes a boolean argument. If set, locks down the personality system call so that the kernel execution domain may not be changed from the default or the personality selected with Personality= directive.

    PrivateMounts

Takes a boolean parameter. If set, the processes of this unit will be run in their own private file system (mount) namespace with all mount propagation from the processes towards the host's main file system namespace turned off. This means any file system mount points established or removed by the unit's processes will be private to them and not be visible to the host.

    PrivateNetwork

Takes a boolean argument. If true, sets up a new network namespace for the executed processes and configures only the loopback network device "lo" inside it. No other network devices will be available to the executed process. This is useful to turn off network access by the executed process. Defaults to false.

    ProtectHostname

Takes a boolean argument. When set, sets up a new UTS namespace for the executed processes. In addition, changing hostname or domainname is prevented. Defaults to off.

    AmbientCapabilities

Controls which capabilities to include in the ambient capability set for the executed process. Takes a whitespace-separated list of capability names, e.g. CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_SYS_PTRACE.

    SecureBits

Controls the secure bits set for the executed process. Takes a space-separated combination of options from the following list: keep-caps, keep-caps-locked, no-setuid-fixup, no-setuid-fixup-locked, noroot, and noroot-locked.

    RestrictSUIDSGID

Takes a boolean argument. If set, any attempts to set the set-user-ID (SUID) or set-group-ID (SGID) bits on files or directories will be denied (for details on these bits see inode.

    SELinuxContext

Set the SELinux security context of the executed process. If set, this will override the automated domain transition. However, the policy still needs to authorize the transition. This directive is ignored if SELinux is disabled.

    AppArmorProfile

Takes a profile name as argument. The process executed by the unit will switch to this profile when started. Profiles must already be loaded in the kernel, or the unit will fail. This result in a non operation if AppArmor is not enabled.

    SmackProcessLabel

Takes a SMACK64 security label as argument. The process executed by the unit will be started under this label and SMACK will decide whether the process is allowed to run or not, based on it.

    SystemCallFilter

Takes a space-separated list of system call names. If this setting is used, all system calls executed by the unit processes except for the listed ones will result in immediate process termination with the SIGSYS signal (whitelisting). If the first character of the list is "~", the effect is inverted: only the listed system calls will result in immediate process termination (blacklisting). Blacklisted system calls and system call groups may optionally be suffixed with a colon (":") and "errno" error number (between 0 and 4095) or errno name such as EPERM, EACCES or EUCLEAN (see errno for a full list).
