import json
import time
import os
import sys

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def format_uptime(seconds):
    mins, secs = divmod(seconds, 60)
    hrs, mins = divmod(mins, 60)
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"

def monitor(stats_file):
    print(f"Monitoring {stats_file}...")
    try:
        while True:
            if os.path.exists(stats_file):
                try:
                    with open(stats_file, 'r') as f:
                        stats = json.load(f)
                    
                    clear_screen()
                    print("="*40)
                    print(f" GFK Real-time Monitor ({'Server' if 'server' in stats_file else 'Client'})")
                    print("="*40)
                    print(f" Uptime:    {format_uptime(stats.get('uptime', 0))}")
                    print(f" Traffic:")
                    print(f"   Download (RX): {stats.get('rx_mb', 0):>8} MB")
                    print(f"   Upload   (TX): {stats.get('tx_mb', 0):>8} MB")
                    print("-" * 40)
                    print(f" Connections:")
                    print(f"   Active TCP:   {stats.get('tcp_count', 0):>10}")
                    print(f"   Active UDP:   {stats.get('udp_count', 0):>10}")
                    print("="*40)
                    print(" Press Ctrl+C to exit")
                    
                except (json.JSONDecodeError, IOError):
                    pass # Wait for next update
            else:
                print(f" Waiting for stats file: {stats_file}")
            
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n Monitoring stopped.")

if __name__ == "__main__":
    target = "gfk_stats.json"
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        target = "gfk_server_stats.json"
    
    monitor(target)
