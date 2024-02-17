import sys
import time
import subprocess
import os
import datetime
import configparser
import shutil
import unicodedata
import re
import json
import signal
import hashlib

from enum import Enum
from pathlib import Path

tmp_path = "target/test"
tmp_path_test_target_dir = f"{tmp_path}/test_target"
tmp_path_test_bkup_dir = f"{tmp_path}/bkup"
def setup(config):

    if os.path.exists(tmp_path):
        shutil.rmtree(tmp_path)

    os.makedirs(tmp_path)
    os.makedirs(tmp_path_test_bkup_dir)
    os.makedirs(tmp_path_test_target_dir)

    with open(f"{tmp_path}/config.ini", "w") as f:
        f.write(config)

def teardown():
    shutil.rmtree(tmp_path)

def run_test(key, config, test_fn):
    setup(config)
    result = run_test_agent(key, test_fn)
    teardown()

    return result

def run_test_agent(key, test_fn):
    cmd = f"{sys.executable} .\\py-agent.py {key} .\\target\\test\\config.ini"
    print(f"Running test: {key}")
    p = subprocess.Popen(cmd, shell=True)
    p.wait()

    result_code = p.returncode
    result = test_fn(p)
    if result is None and result_code == 0:
        print("Passed")
    else:
        print("Failed")

    return {
        "key": key,
        "result": "passed" if (result is None and result_code == 0) else "failed",
    }

def boot_test(p):
    # nothing to test, so long as the test does not throw an exception we're good
    assert(True)

def backup_test(p):
    backup_files = os.listdir(tmp_path_test_bkup_dir)

    # Should only have a single manifest and a single backup
    assert(len(backup_files) == 2)
    manifest_file_name = next((x for x in backup_files if x.endswith('.json')), None)

    # Should have the manifest .json
    assert(manifest_file_name)
    cfg = None
    with open(f"{tmp_path_test_bkup_dir}/{manifest_file_name}") as f:
        cfg = json.loads(f.read())

    # Cfg json should be valid and available
    assert(cfg)

    # We should only have a single backup
    assert(len(cfg["bkups"]) == 1)

    # The top-level hash should match the single backup hash
    assert(cfg["bkups"][0]["bkup_hash"] == cfg["last_bkup_hash"])

    # The timestamp for the single backup should be close to the final backup time
    assert(cfg["bkups"][0]["timestamp"] - cfg["last_bkup"] < 10.0)

    # TODO: Check that the backup has been made per specifications

def generate_config(cwd):

    if os.name == 'nt':
        return fr"""
        [global]
        poll_interval = 0.25
        exec_launch_cooloff = 0.25
        exec_dir = C:\Windows
        exec_name = notepad.exe
        exec_setup_script =
        exec_startup_script =
        exec_poll_name =
        exec_args =
        backup_interval =
        backup_total_to_keep = 10
        backup_target_dir = {cwd}/target/test/test_target
        backup_target_hash_dir =
        backup_dest_dir = {cwd}/target/test/bkup
        sample_runtime = 1
        kill_process_on_exit = True

        [boot_test]

        [backup_test]
        sample_runtime = 1
        exec_dir = C:\Windows
        exec_name = notepad.exe
        backup_interval = 0.25
        backup_total_to_keep = 1
        """
    else:
        # TODO: Linux?
        return ""

def main():
    config = generate_config(os.getcwd())
    assert(len(config) > 0)
    results = [
        run_test("boot_test", config, boot_test),
        run_test("backup_test", config, backup_test),
        ]

    print(results)

if __name__ == "__main__":
    main()