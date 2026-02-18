"""
Script to check running executables against VirusTotal API
"""

import os
import sys
import hashlib
import time
import requests
import psutil
from collections import defaultdict

# VirusTotal API Key
VT_API_KEY = "fe452701ce0d8a59f68862d7372f8417f06d4a3340f8d747f63cf5bec3ba3e01"
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

def get_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        return None

def get_running_executables():
    """Get all unique running executables with their process info"""
    executables = defaultdict(list)
    
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = proc.info['exe']
            if exe_path and os.path.exists(exe_path):
                executables[exe_path].append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name']
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return executables

def check_virustotal(file_hash):
    """Check a file hash against VirusTotal API"""
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(VT_API_URL + file_hash, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"status": "not_found"}
        elif response.status_code == 429:
            return {"status": "rate_limited"}
        else:
            return {"status": "error", "code": response.status_code}
    except requests.RequestException as e:
        return {"status": "error", "message": str(e)}

def analyze_vt_result(result):
    """Analyze VirusTotal result and return summary"""
    if result.get("status") == "not_found":
        return {"verdict": "UNKNOWN", "message": "File not found in VirusTotal database"}
    
    if result.get("status") == "rate_limited":
        return {"verdict": "RATE_LIMITED", "message": "API rate limit reached"}
    
    if result.get("status") == "error":
        return {"verdict": "ERROR", "message": f"Error: {result.get('message', result.get('code', 'Unknown'))}"}
    
    try:
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        total = malicious + suspicious + harmless + undetected
        
        if malicious > 0 or suspicious > 0:
            verdict = "⚠️  SUSPICIOUS" if suspicious > 0 and malicious == 0 else "🚨 MALICIOUS"
        else:
            verdict = "✅ CLEAN"
        
        return {
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "name": attributes.get("meaningful_name", "N/A")
        }
    except Exception as e:
        return {"verdict": "ERROR", "message": str(e)}

def print_separator():
    print("=" * 80)

def main():
    print_separator()
    print("🔍 RUNNING PROCESS VIRUSTOTAL SCANNER")
    print_separator()
    print()
    
    print("[*] Gathering running executables...")
    executables = get_running_executables()
    print(f"[*] Found {len(executables)} unique executables")
    print()
    
    results = {
        "clean": [],
        "suspicious": [],
        "malicious": [],
        "unknown": [],
        "error": []
    }
    
    for idx, (exe_path, processes) in enumerate(executables.items(), 1):
        print(f"[{idx}/{len(executables)}] Checking: {os.path.basename(exe_path)}")
        print(f"    Path: {exe_path}")
        print(f"    PIDs: {', '.join(str(p['pid']) for p in processes)}")
        
        # Calculate hash
        file_hash = get_file_hash(exe_path)
        if not file_hash:
            print(f"    ❌ Could not calculate hash (access denied or file not found)")
            results["error"].append({"path": exe_path, "reason": "hash_failed"})
            print()
            continue
        
        print(f"    SHA256: {file_hash}")
        
        # Check VirusTotal
        vt_result = check_virustotal(file_hash)
        analysis = analyze_vt_result(vt_result)
        
        verdict = analysis.get("verdict", "UNKNOWN")
        
        if "MALICIOUS" in verdict:
            print(f"    🚨 RESULT: {verdict} ({analysis.get('malicious', 0)}/{analysis.get('total', 0)} detections)")
            results["malicious"].append({
                "path": exe_path,
                "hash": file_hash,
                "detections": analysis.get('malicious', 0),
                "total": analysis.get('total', 0),
                "processes": processes
            })
        elif "SUSPICIOUS" in verdict:
            print(f"    ⚠️  RESULT: {verdict} ({analysis.get('suspicious', 0)} suspicious)")
            results["suspicious"].append({
                "path": exe_path,
                "hash": file_hash,
                "analysis": analysis,
                "processes": processes
            })
        elif "CLEAN" in verdict:
            print(f"    ✅ RESULT: {verdict} (0/{analysis.get('total', 0)} detections)")
            results["clean"].append({"path": exe_path, "hash": file_hash})
        elif "UNKNOWN" in verdict:
            print(f"    ❓ RESULT: Not in VirusTotal database")
            results["unknown"].append({"path": exe_path, "hash": file_hash})
        else:
            print(f"    ❌ RESULT: {analysis.get('message', 'Error checking file')}")
            results["error"].append({"path": exe_path, "reason": analysis.get('message', 'unknown')})
        
        print()
        
        # Rate limiting - VirusTotal free API allows 4 requests per minute
        if idx < len(executables):
            time.sleep(15)  # Wait 15 seconds between requests
    
    # Print summary
    print_separator()
    print("📊 SCAN SUMMARY")
    print_separator()
    print(f"Total executables scanned: {len(executables)}")
    print(f"✅ Clean:      {len(results['clean'])}")
    print(f"⚠️  Suspicious: {len(results['suspicious'])}")
    print(f"🚨 Malicious:  {len(results['malicious'])}")
    print(f"❓ Unknown:    {len(results['unknown'])}")
    print(f"❌ Errors:     {len(results['error'])}")
    print()
    
    # Print details for concerning files
    if results["malicious"]:
        print_separator()
        print("🚨 MALICIOUS FILES DETECTED:")
        print_separator()
        for item in results["malicious"]:
            print(f"  File: {item['path']}")
            print(f"  Hash: {item['hash']}")
            print(f"  Detections: {item['detections']}/{item['total']}")
            print(f"  Running as PIDs: {', '.join(str(p['pid']) for p in item['processes'])}")
            print()
    
    if results["suspicious"]:
        print_separator()
        print("⚠️  SUSPICIOUS FILES:")
        print_separator()
        for item in results["suspicious"]:
            print(f"  File: {item['path']}")
            print(f"  Hash: {item['hash']}")
            print()
    
    if results["unknown"]:
        print_separator()
        print("❓ UNKNOWN FILES (not in VirusTotal database):")
        print_separator()
        for item in results["unknown"]:
            print(f"  File: {item['path']}")
            print(f"  Hash: {item['hash']}")
            print()

if __name__ == "__main__":
    main()
