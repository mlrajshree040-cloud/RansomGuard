from ransomguard.scanner import SystemScanner


def main():
    print("=" * 60)
    print("  RansomGuard — Full System Scan")
    print("=" * 60)

    scanner = SystemScanner()
    print(f"\nScanning {len(scanner.root_paths)} target folders:")
    for r in scanner.root_paths:
        print(f"   - {r}")
    print("\nScanning... (may take 1-3 minutes)\n")

    def progress(scanned, threats, current):
        name = current.split("\\")[-1][:45]
        print(f"   scanned={scanned:5d}  threats={threats}  {name:<45s}", end="\r")

    result = scanner.scan(progress_callback=progress)

    print("\n")
    print("=" * 60)
    print(f"  Scan Complete")
    print("=" * 60)
    print(f"  Files scanned:   {result['scanned']}")
    print(f"  Files skipped:   {result['skipped']}")
    print(f"  Threats found:   {result['threats']}")
    print(f"  Duration:        {result['duration']}s")
    print("=" * 60)

    if result["threats"] > 0:
        print("\nSUSPICIOUS FILES:\n")
        for t in result["threat_list"]:
            print(f"  [{t['verdict']}] {t['name']}")
            print(f"     Path:    {t['path']}")
            for r in t["reasons"]:
                print(f"     Reason:  {r}")
            if t["sha256"]:
                print(f"     SHA256:  {t['sha256'][:32]}...")
            print()
    else:
        print("\nNo threats detected. System is clean.")


if __name__ == "__main__":
    main()