This patch supplements the TTY audit function in the `Linux Kernel`.  The
existing auditing capabilities only record half of the TTY conversation. 
This leads to lost data for two situations:

* We cannot see what the user sent to the TTY, only what the TTY sends to them
* if the TTY user turns off echo (stty -echo), the built in auditing records nothing

Bidirectional record logging provided by this patch records all TTY data in
both channels (stderr and stdout are in the same channel) and records data
even when `stty -echo` is used.  All byte data is recorded, including all
control characters.

A simple `Python 3` script is included for printing a strong representation of
actual TTY appearance on the user's terminal.

example `audit-log-print.py` output:

```
┌[✓  Mon Feb 05 21:18 root@hive-poc  [~]
└─>cat /var/log/audit/audit.log|python audit-log-print.py 
◀ david              1452827555.543┆ Last login: Thu Jan 14 21:58:21 2016 from 127.0.0.1↩↲
▶ david              1452827561.176┆ w↩
◀ david              1452827561.176┆ <title='david@ak:~'/>
◀ david              1452827561.176┆ [david@ak ~]$ w↲
◀ david              1452827561.183┆  22:12:41 up 19 min,  3 users,  load average: 0.56, 0.30, 0.14↲
◀ david              1452827561.183┆ USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT↲
◀ david              1452827561.186┆ root     pts/0     21:55   14:40   0.02s  0.00s tail -f /var/log/audit/audit.log↲
◀ david              1452827561.186┆ root     pts/1     21:55    1.00s  0.09s  0.01s ssh david@0↲
◀ david              1452827561.189┆ david    pts/2     22:12    1.00s  0.00s  0.00s w↲
▶ david              1452827562.613┆ exit↩
◀ david              1452827562.613┆ <title='david@ak:~'/>
◀ david              1452827562.613┆ [david@ak ~]$ exit↲
◀ david              1452827562.613┆ logout↲
■ non-root           1467310857.488┆ ❎
```
