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
    # no-op check, just not exceptions
    pass

def backup_test(p):
    # TODO: Check that the backup has been made per specifications
    pass

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
        backup_target_dir =
        backup_target_hash_dir =
        backup_dest_dir =
        sample_runtime =
        kill_process_on_exit = True

        [boot_test]
        sample_runtime = 1

        [backup_test]
        sample_runtime = 3
        exec_dir = C:\Windows
        exec_name = notepad.exe
        backup_interval = 1
        backup_target_dir = {cwd}/target/test/test_target
        backup_dest_dir = {cwd}/target/test/bkup
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