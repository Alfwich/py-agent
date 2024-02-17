import sys
import subprocess
import os
import shutil
import json
import time
import signal

import agent

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
    print(f"Running test: {key}")

    prev_argv = sys.argv
    prev_cwd = os.getcwd()
    sys.argv = [".\\agent.py ", f"{key}", ".\\target\\test\\config.ini"]
    agent.main.test_hook = test_hook
    test_hook.init_timestamp = time.time()

    result = None
    try:
        agent.main()
        os.chdir(prev_cwd)
        test_fn()
    except Exception as e:
        print(f"Failed test: {key} due to: {e=}")
        result = False

    agent.main.test_hook = None

    if result is None:
        print("Passed")
    else:
        print("Failed")

    return {
        "key": key,
        "result": "passed" if result is None else "failed",
    }


def boot_test():
    assert True, 'NOOP'


def backup_test():
    backup_files = os.listdir(tmp_path_test_bkup_dir)

    assert len(backup_files) == 2, 'Should only have 2 files in backup directory'
    manifest_file_name = next(
        (x for x in backup_files if x.endswith('.json')), None)

    assert manifest_file_name, 'Should have the manifest .json'
    cfg = None
    with open(f"{tmp_path_test_bkup_dir}/{manifest_file_name}") as f:
        cfg = json.loads(f.read())

    assert cfg, 'Cfg json should be valid'

    assert len(cfg["bkups"]) == 1, 'We should only have a single backup'

    assert cfg["bkups"][0]["bkup_hash"] == cfg["last_bkup_hash"], 'Top level hash should match the single backup hash'

    assert cfg["bkups"][0]["timestamp"] - \
        cfg["last_bkup"] < 10.0, 'The timestamp for the single backup should be close to the final backup time'


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
        test_enabled = True
        test_sample_runtime = 1
        test_kill_process_on_exit = True

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


def test_hook(op_config):
    runtime = agent.get_field_or_default(op_config, 'test_sample_runtime', 0)
    print(runtime)
    if runtime > 0 and time.time() - test_hook.init_timestamp > runtime:
        agent.signal_handler(signal.SIGINT, None)

    if agent.get_field_or_default(op_config, 'test_kill_process_on_exit', False) and agent.get_agent_state() is agent.AgentState.SHUTTING_DOWN:
        pinfo = agent.get_process_info(op_config)
        if not pinfo is None:
            os.kill(int(pinfo['pid']), signal.SIGINT)


def main():
    config = generate_config(os.getcwd())
    assert (len(config) > 0)
    results = [
        run_test("boot_test", config, boot_test),
        run_test("backup_test", config, backup_test),
    ]

    print(results)


if __name__ == "__main__":
    main()
