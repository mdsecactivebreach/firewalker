# FireWalker Instructions

This repo contains a simple library which can be used to add FireWalker hook bypass capabilities to existing code; the FireWalker concept is described on the MDSec blog at <URL>.

To use the library just `#include` the FireWalker.h source file within existing C++ code and wrap API calls which may be hooked with `FIREWALK`, e.g.:

```c++
    if (!FIREWALK(QueueUserAPC((PAPCFUNC)lpvRemote, hRemoteThread, NULL)))
    {
        printf("QueueUserAPC failed\n");
        return 1;
    }
```

At present FireWalker only supports 32-bit code with 32-bit hooks; x64 and WoW64 support may be added if the concept is popular.

