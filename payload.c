// SPDX-License-Identifier: GPL-3.0-or-later
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <ps5/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "signatures.h"
#ifndef RESTORE
#define RESTORE 0
#endif

/* Notification layout used by the PS5 Payload SDK hello_world sample. */
typedef struct {
 char reserved[45];
 char message[3075];
} notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static char debug_report[3075];
static size_t debug_report_used;

static void debug_log(const char *message) {
 puts(message);
 size_t remaining=sizeof(debug_report)-debug_report_used;
 if(remaining>1){
  int written=snprintf(debug_report+debug_report_used,remaining,"%s\n",message);
  if(written>0)debug_report_used+=(size_t)written<remaining?(size_t)written:remaining-1;
 }
}
static void debug_error(const char *message) {
 int saved_errno=errno;
 char detail[256];
 snprintf(detail,sizeof(detail),"%s: errno=%d (%s)",message,saved_errno,strerror(saved_errno));
 debug_log(detail);
 errno=saved_errno;
}
static void debug_toast(const char *message) {
 notify_request_t req={0};
 snprintf(req.message,sizeof(req.message),"%s",message);
 if(sceKernelSendNotificationRequest(0,&req,sizeof(req),0)<0)
  perror("Could not send PS5 debug notification");
}

/* FreeBSD/PS5 signals syscall errors with carry set and a positive errno.
 * Capture carry before testing the result; SDK raw stubs do not normalize it.
 */
static long checked_syscall4(long number,long a,long b,long c,long d) {
 register long fourth __asm__("r10")=d;
 long value;
 unsigned char failed;
 __asm__ volatile("syscall\n\tsetc %1"
  : "=a"(value), "=qm"(failed)
  : "a"(number), "D"(a), "S"(b), "d"(c), "r"(fourth)
  : "rcx", "r11", "memory", "cc");
 if(failed){errno=(int)value;return -1;}
 return value;
}
static int checked_ptrace(int op,pid_t pid,caddr_t addr,int data) {
 return (int)checked_syscall4(26,(long)op,(long)pid,(long)(uintptr_t)addr,(long)data);
}
static pid_t checked_waitpid(pid_t pid,int *status,int options) {
 return (pid_t)checked_syscall4(7,(long)pid,(long)(uintptr_t)status,(long)options,0L);
}

/* Scope debugger credentials to this payload; restore even after partial setup. */
struct tracing_credentials {
 pid_t self;
 uint64_t authid;
 uint8_t caps[16];
 int dirty;
};
static int restore_tracing_credentials(struct tracing_credentials *saved) {
 if(!saved->dirty)return 0;
 int caps_rc=kernel_set_ucred_caps(saved->self,saved->caps);
 int auth_rc=kernel_set_ucred_authid(saved->self,saved->authid);
 uint8_t caps[16];
 int read_rc=kernel_get_ucred_caps(saved->self,caps);
 if(caps_rc||auth_rc||read_rc||
    kernel_get_ucred_authid(saved->self)!=saved->authid||
    memcmp(caps,saved->caps,sizeof(caps)))return -1;
 saved->dirty=0;
 return 0;
}
static int enable_tracing_credentials(struct tracing_credentials *saved) {
 uint8_t caps[16];
 saved->self=getpid();
 saved->authid=kernel_get_ucred_authid(saved->self);
 if(!saved->authid||kernel_get_ucred_caps(saved->self,saved->caps))return -1;
 memset(caps,0xff,sizeof(caps));
 saved->dirty=1;
 if(kernel_set_ucred_authid(saved->self,0x4800000000010003ULL)||
    kernel_set_ucred_caps(saved->self,caps))return -1;
 uint8_t actual[16];
 if(kernel_get_ucred_authid(saved->self)!=0x4800000000010003ULL||
    kernel_get_ucred_caps(saved->self,actual)||memcmp(actual,caps,sizeof(caps)))return -1;
 return 0;
}

static const unsigned char original[8]={0x41,0x80,0x3f,0x00,0x74,0xa3,0x4c,0x89};
static const unsigned char patched[8] ={0x41,0x80,0x3f,0x20,0x76,0xa3,0x4c,0x89};
static int find_shell(void) {
 int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};size_t size=0;
 if(sysctl(mib,4,0,&size,0,0))return -1;
 unsigned char *buf=malloc(size);if(!buf)return -1;
 if(sysctl(mib,4,buf,&size,0,0)){free(buf);return -1;}
 int pid=-1;
 for(size_t at=0;at+sizeof(struct kinfo_proc)<=size;){
  struct kinfo_proc *p=(void*)(buf+at);
  if(p->ki_structsize<=0||(size_t)p->ki_structsize<sizeof(*p)||at+p->ki_structsize>size){pid=-1;break;}
  if(!strcmp(p->ki_comm,"SceShellCore")){if(pid!=-1){pid=-1;break;}pid=p->ki_pid;}
  at+=p->ki_structsize;
 }
 free(buf);return pid;
}
static int read_match(int pid,uintptr_t base,size_t off,const unsigned char *expected,size_t len){
 unsigned char buf[128];if(len>sizeof(buf))return 0;
 return !kernel_proc_copyout(pid,base+off,buf,len)&&!memcmp(buf,expected,len);
}
int main(void){
 struct tracing_credentials credentials={0};
 int result=1,attached=0,pid=-1,status=0;uint32_t handle=0;uintptr_t base=0,site=0;
 unsigned char current[8];const unsigned char *desired=RESTORE?original:patched;
 debug_toast(RESTORE?"Service ID guard: starting restore":"Service ID guard: starting apply");
 debug_log(RESTORE?"Service ID guard: restore":"Service ID guard: apply");
 pid=find_shell();if(pid<=0||pid==getpid()){debug_log("Refused: requires separate SceShellCore process");goto done;}
 if(kernel_dynlib_handle(pid,"SceShellCore.elf",&handle)||!(base=kernel_dynlib_mapbase_addr(pid,handle))){debug_log("Refused: cannot resolve ShellCore mapping");goto done;}
 site=base+0x1527ff0;
 if(!read_match(pid,base,0x1527faa,sig_before,sizeof(sig_before))||
    !read_match(pid,base,0x1527ff6,sig_after,sizeof(sig_after))||
    !read_match(pid,base,0x26f238,sig_throw,sizeof(sig_throw))){debug_log("Refused: build signatures differ");goto done;}
 debug_log("ShellCore mapping and build signatures confirmed");
 if(enable_tracing_credentials(&credentials)){debug_log("Refused: cannot enable tracing credentials");goto done;}
 debug_log("Temporary tracing credentials verified");
 if(checked_ptrace(PT_ATTACH,pid,0,0)!=0){debug_error("Refused: PT_ATTACH");goto done;}attached=1;
 debug_log("PT_ATTACH confirmed: return=0 (checked syscall)");
 int stopped=0;
 for(int i=0;i<300;i++){
  int got=checked_waitpid(pid,&status,WNOHANG);
  if(got==pid){stopped=WIFSTOPPED(status);break;}
  if(got<0){if(errno==EINTR){usleep(10000);continue;}debug_error("waitpid failed");break;}
  usleep(10000);
 }
 if(!stopped){debug_log("Refused: target stop not confirmed");goto done;}
 debug_log("Target stop confirmed");
 int n=checked_ptrace(PT_GETNUMLWPS,pid,0,0);
 if(n<=0||n>4096){debug_log("Refused: cannot enumerate threads");goto done;}
 lwpid_t *threads=calloc(n,sizeof(*threads));if(!threads){debug_log("Refused: cannot allocate thread list");goto done;}
 int got=checked_ptrace(PT_GETLWPLIST,pid,(caddr_t)threads,n);
 if(got!=n){free(threads);debug_log("Refused: incomplete thread list");goto done;}
 for(int i=0;i<n;i++){
  struct reg regs;
  if(checked_ptrace(PT_GETREGS,threads[i],(caddr_t)&regs,0)<0||
    ((uintptr_t)regs.r_rip>=site&&(uintptr_t)regs.r_rip<site+8)){
   free(threads);debug_log("Refused: thread state unavailable or inside patch window; retry later");goto done;
  }
 }
 free(threads);
 debug_log("Thread patch-window checks passed");
 if(kernel_proc_copyout(pid,site,current,8)){debug_log("Refused: cannot read patch site");goto done;}
 if(!memcmp(current,desired,8)){debug_log("Already in requested state");result=0;goto done;}
 if(memcmp(current,RESTORE?patched:original,8)){debug_log("Refused: unexpected patch-site bytes");goto done;}
 if(!read_match(pid,base,0x1527faa,sig_before,sizeof(sig_before))||!read_match(pid,base,0x1527ff6,sig_after,sizeof(sig_after))){debug_log("Refused: code changed while attaching");goto done;}
 if(kernel_proc_copyin(pid,desired,site,8)||!read_match(pid,base,0x1527ff0,desired,8)){
  int rollback=kernel_proc_copyin(pid,current,site,8);
  if(rollback||!read_match(pid,base,0x1527ff0,current,8))debug_log("ERROR: restoration could not be verified; reboot required");
  else debug_log("Write failed; original state restored");
  goto done;
 }
 debug_log(RESTORE?"Original collector restored":"Leading whitespace/control service IDs skipped; RAM patch verified");result=0;
done:
 if(attached&&checked_ptrace(PT_DETACH,pid,(caddr_t)1,0)<0){debug_error("ERROR: detach; reboot may be required");result=1;}
 if(restore_tracing_credentials(&credentials)){debug_log("ERROR: credential restoration could not be verified");result=1;}
 else if(credentials.self)debug_log("Original tracing credentials restored");
 debug_log(result?"Service ID guard result: not applied / error":"Service ID guard result: success");
 debug_toast(debug_report);
 return result;
}
