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
    run_test_agent(key, test_fn)
    teardown()

def run_test_agent(key, test_fn):
    cmd = f"{sys.executable} .\\py-agent.py {key} .\\target\\test\\config.ini"
    print(f"[tests] Running test: {key}")
    p = subprocess.Popen(cmd, shell=True)
    test_fn(p)
    p.wait()
    print("[tests] Done!")

def boot_test(p):
    pass

def generate_config(cwd):

    if os.name == 'nt':
        return fr"""
        [global]
        poll_interval = 15
        exec_launch_cooloff = 15
        exec_dir =
        exec_name =
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

        [boot_test]
        sample_runtime = 5
        exec_dir = C:\Windows
        exec_name = notepad.exe
        backup_interval = 10
        backup_target_dir = {cwd}/target/test/test_target
        backup_dest_dir = {cwd}/target/test/bkup
        backup_total_to_keep = 5
        poll_interval = 3
        exec_launch_cooloff = 5
        """
    else:
        # TODO: Linux?
        return ""

def main():
    config = generate_config(os.getcwd())
    run_test("boot_test", config, boot_test)

if __name__ == "__main__":
    main()