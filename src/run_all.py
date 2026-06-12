import subprocess
import sys

def run_task(task_file, task_name):
    print(f"\n{'='*60}")
    print(f"[START] {task_name}")
    print(f"{'='*60}\n")
    
    result = subprocess.run([sys.executable, f"src/{task_file}"], capture_output=False)
    
    if result.returncode != 0:
        print(f"[ERROR] {task_name} failed with code {result.returncode}")
        sys.exit(1)
    
    print(f"\n[DONE] {task_name} completed successfully\n")

def main():
    print("[INFO] Starting all tasks...")
    
    run_task("task1_collect_mozilla.py", "Task 1: Collect Mozilla CVEs")
    run_task("task2_enrich_mitre.py", "Task 2: Enrich with MITRE data")
    run_task("task3_json_to_xml.py", "Task 3: Convert JSON to XML")
    run_task("task4_validate.py", "Task 4: Validate JSON")
    run_task("task5_load_db.py", "Task 5: Load to database")
    
    print("\n" + "="*60)
    print("[SUCCESS] All tasks completed!")
    print("="*60)

if __name__ == "__main__":
    main()
