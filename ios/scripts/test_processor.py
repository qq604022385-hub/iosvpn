#!/usr/bin/env python3
"""Exercise the real strongSwan worker pool, independently of Apple/device acceptance."""
from pathlib import Path
import os,sys,subprocess,tempfile,shutil,shlex
from prepare_source import IOS,ROOT,copy_tree

def run(args,cwd,env):
    result=subprocess.run(list(map(str,args)),cwd=cwd,env=env,capture_output=True,text=True,encoding="utf8",errors="replace",timeout=120)
    print(result.stdout,end="");print(result.stderr,end="",file=sys.stderr);result.check_returncode()

def main():
    env=dict(os.environ);(IOS/"build").mkdir(exist_ok=True)
    if os.name=="nt":
        prefix=ROOT/"windows/build-deps/toolchain/mingw64";source=ROOT/"windows/build-deps/strongswan-6.1.0"
        compiler=prefix/"bin/gcc.exe";env["PATH"]=str(prefix/"bin")+os.pathsep+env.get("PATH","")
        run([compiler,"--version"],IOS,env)
        relative=lambda p:os.path.relpath(p,IOS)
        flags=["-B"+relative(prefix/"lib")+os.sep]
        flags += ["-B"+relative(p)+os.sep for p in (prefix/"lib/gcc").glob("*/*") if p.is_dir()]
        link=["-L"+relative(prefix/"lib"),"-lcrypto","-lws2_32","-liphlpapi","-lbcrypt"]
        args=[compiler,"-std=gnu11",*flags,"-include",relative(source/"config.h"),"-I"+relative(source/"src/libstrongswan"),"NativeTests/processor_test.c",relative(source/"src/libstrongswan/.libs/libstrongswan.a"),*link,"-o","build/processor-test.exe"]
        run(args,IOS,env);run([IOS/"build/processor-test.exe"],IOS,env);return
    if sys.platform!="darwin":raise SystemExit("This test runner currently supports Windows and macOS hosts")
    for key in ["SDKROOT","IPHONEOS_DEPLOYMENT_TARGET","MACOSX_DEPLOYMENT_TARGET"]:env.pop(key,None)
    sdk=subprocess.check_output(["xcrun","--sdk","macosx","--show-sdk-path"],env=env,text=True,timeout=30).strip()
    compiler=subprocess.check_output(["xcrun","--sdk","macosx","--find","clang"],env=env,text=True,timeout=30).strip()
    env["SDKROOT"]=sdk;env["CC"]=compiler;env["CFLAGS"]=shlex.join(["-std=gnu11","-isysroot",sdk,"-O2"])
    env["LDFLAGS"]=shlex.join(["-isysroot",sdk]);env.pop("CPPFLAGS",None)
    with tempfile.TemporaryDirectory(prefix="processor-host-",dir=IOS/"build") as temp:
        source=copy_tree(Path(temp)/"source")
        run(["bash","autogen.sh"],source,env)
        run(["./configure","--disable-defaults","--enable-static","--disable-shared","--enable-monolithic","--with-printf-hooks=builtin","--with-capabilities=no","--with-strongswan-conf="],source,env)
        run(["make","-j2","-C","src/libstrongswan"],source,env)
        executable=Path(temp)/"processor-test"
        run([compiler,"-std=gnu11","-isysroot",sdk,"-include",source/"config.h","-I"+str(source/"src/libstrongswan"),IOS/"NativeTests/processor_test.c",source/"src/libstrongswan/.libs/libstrongswan.a","-lm","-o",executable],IOS,env)
        run([executable],IOS,env)

if __name__=="__main__":main()
