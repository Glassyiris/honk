#!/usr/bin/env python3
import argparse, glob, json, os, re, signal, subprocess, sys, time
from pathlib import Path

TARGET="192.168.223.2"
ROOT="/root/bench-20261020"
CLK=os.sysconf("SC_CLK_TCK")

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd,str), capture_output=True, text=True, **kw)

def cleanup_daens():
    sh(f"for i in $(seq 1 256); do findmnt -T /run/netns/daens >/dev/null 2>&1 || break; umount -l /run/netns/daens 2>/dev/null || break; done; rm -f /run/netns/daens")
    sh("ip link del dae0 2>/dev/null")

def stop_all():
    sh("pkill -f '^"+ROOT+"/honk-candidate' 2>/dev/null; pkill -f '^"+ROOT+"/honk-prof' 2>/dev/null; pkill -f '^"+ROOT+"/bin/dae run' 2>/dev/null")
    time.sleep(1)
    sh("pkill -9 -f '^"+ROOT+"/honk-candidate' 2>/dev/null; pkill -9 -f '^"+ROOT+"/honk-prof' 2>/dev/null; pkill -9 -f '^"+ROOT+"/bin/dae run' 2>/dev/null")
    cleanup_daens()

def stat_read(pid):
    parts=Path(f"/proc/{pid}/stat").read_text().split()
    return int(parts[13]), int(parts[14])

def io_read(pid):
    out={}
    for line in Path(f"/proc/{pid}/io").read_text().splitlines():
        k,v=line.split(":",1); out[k]=int(v)
    return out

def status_read(pid):
    out={}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(("VmRSS:","voluntary_ctxt_switches:","nonvoluntary_ctxt_switches:")):
            k,v=line.split(":",1); out[k]=int(v.strip().split()[0])
    return out

def threads(pid):
    out={}
    for p in glob.glob(f"/proc/{pid}/task/*/stat"):
        try:
            parts=Path(p).read_text().split()
            tid=p.split("/")[-2]
            out[tid]={"comm":parts[1],"utime":int(parts[13]),"stime":int(parts[14])}
        except Exception:
            pass
    return out

def snapshot(pid):
    u,s=stat_read(pid)
    return {"utime":u,"stime":s,"io":io_read(pid),"status":status_read(pid),"threads":threads(pid)}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--engine",required=True,choices=["honk","dae"])
    ap.add_argument("--bin",required=True)
    ap.add_argument("--config",required=True)
    ap.add_argument("--label",required=True)
    ap.add_argument("--port",required=True,type=int)
    ap.add_argument("--direction",choices=["down","up"],default="down")
    ap.add_argument("--seconds",type=int,default=8)
    ap.add_argument("--perfstat",action="store_true")
    ap.add_argument("--perfrecord",action="store_true")
    args=ap.parse_args()
    stop_all()
    outdir=Path(ROOT)/"prof"
    outdir.mkdir(exist_ok=True)
    log=open(outdir/f"{args.label}.engine.log","w")
    cmd=[args.bin,"--config",args.config] if args.engine=="honk" else [args.bin,"run","-c",args.config]
    proc=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        if args.engine=="honk":
            for _ in range(25):
                if sh("curl -s -m 1 http://127.0.0.1:9090/version").returncode==0: break
                if proc.poll() is not None: raise RuntimeError("honk exited")
                time.sleep(1)
        else:
            for _ in range(30):
                if sh("ip link show dae0").returncode==0 and sh("ip netns list").stdout.find("daens")>=0: break
                if proc.poll() is not None: raise RuntimeError("dae exited")
                time.sleep(1)
            time.sleep(2)
        pid=proc.pid
        if not Path(f"/proc/{pid}/exe").exists(): raise RuntimeError("engine pid missing")
        # warm the proxy session, then measure
        warm=["ip","netns","exec","lab","iperf3","-c",TARGET,"-p",str(args.port),"-t","1","-J"]
        if args.direction=="down": warm.insert(-1,"-R")
        sh(warm)
        perf=None; perf_path=outdir/f"{args.label}.perfstat.txt"
        rec=None; rec_path=outdir/f"{args.label}.perf.data"
        if args.perfrecord:
            rec=subprocess.Popen(["perf","record","-a","-e","cpu-clock","-F","499","-g","--call-graph","dwarf,8192","-o",str(rec_path),"--","sleep",str(args.seconds+1)],stdout=subprocess.DEVNULL,stderr=open(outdir/f"{args.label}.perfrecord.err","w"))
            time.sleep(0.5)
        if args.perfstat:
            perf=subprocess.Popen(["perf","stat","-p",str(pid),"--per-thread","-e",
                "task-clock,cycles,instructions,branches,branch-misses,cache-references,cache-misses,context-switches,cpu-migrations,page-faults",
                "-o",str(perf_path),"--","sleep",str(args.seconds+1)])
            time.sleep(0.3)
        before=snapshot(pid); t0=time.monotonic()
        iperf=["ip","netns","exec","lab","iperf3","-c",TARGET,"-p",str(args.port),"-t",str(args.seconds),"-J"]
        if args.direction=="down": iperf.insert(-1,"-R")
        run=sh(iperf)
        t1=time.monotonic(); after=snapshot(pid)
        if perf is not None:
            perf.wait(timeout=args.seconds+10)
        if rec is not None:
            rec.wait(timeout=args.seconds+20)
        (outdir/f"{args.label}.iperf.json").write_text(run.stdout)
        try:
            d=json.loads(run.stdout); rec=d["end"]["sum_received"]["bits_per_second"]/1e6
        except Exception:
            rec=None
        du=(after["utime"]-before["utime"])/CLK; ds=(after["stime"]-before["stime"])/CLK; elapsed=t1-t0
        th=[]
        for tid,a in after["threads"].items():
            b=before["threads"].get(tid)
            if not b: continue
            u=(a["utime"]-b["utime"])/CLK; s=(a["stime"]-b["stime"])/CLK
            if u+s > 0.001: th.append({"tid":tid,"comm":a["comm"],"user":round(u,4),"sys":round(s,4),"total":round(u+s,4)})
        th.sort(key=lambda x:-x["total"])
        all_before=sum(v["utime"]+v["stime"] for v in before["threads"].values())/CLK
        all_after=sum(v["utime"]+v["stime"] for v in after["threads"].values())/CLK
        result={
          "label":args.label,"engine":args.engine,"pid":pid,"port":args.port,"direction":args.direction,
          "mbps":None if rec is None else round(rec,1),"elapsed_s":round(elapsed,3),
          "user_cores":round(du/elapsed,4),"sys_cores":round(ds/elapsed,4),"total_cores":round((du+ds)/elapsed,4),
          "all_thread_cores":round((all_after-all_before)/elapsed,4),
          "io":{"rchar_MB":round((after["io"]["rchar"]-before["io"]["rchar"])/1e6,2),
                "wchar_MB":round((after["io"]["wchar"]-before["io"]["wchar"])/1e6,2),
                "syscr":after["io"]["syscr"]-before["io"]["syscr"],
                "syscw":after["io"]["syscw"]-before["io"]["syscw"]},
          "rss_kb":after["status"].get("VmRSS"),
          "voluntary_ctxt":after["status"].get("voluntary_ctxt_switches",0)-before["status"].get("voluntary_ctxt_switches",0),
          "nonvoluntary_ctxt":after["status"].get("nonvoluntary_ctxt_switches",0)-before["status"].get("nonvoluntary_ctxt_switches",0),
          "threads":th[:8],
          "perfstat":str(perf_path) if args.perfstat else None,
          "perfrecord":str(rec_path) if args.perfrecord else None,
        }
        (outdir/f"{args.label}.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result))
    finally:
        proc.terminate()
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
        log.close()
        stop_all()

if __name__=="__main__": main()
