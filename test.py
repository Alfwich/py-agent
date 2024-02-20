from enum import Enum
import sys
import os
import shutil
import json
import time
import signal
import traceback

import agent

from pathlib import Path

tmp_path = f"{os.getcwd()}/target/test"
tmp_path_test_target_dir = f"{tmp_path}/test_target"
tmp_path_test_bkup_dir = f"{tmp_path}/bkup"


class TestFnMode(Enum):
    SETUP = 0
    TICK = 1
    CHECK = 2


class TestResult(Enum):
    PASSED = True
    FAILED = False


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


def run_test(test_fn):
    config = test_fn(TestFnMode.SETUP)
    setup(config)
    result = run_test_agent('test', test_fn)
    teardown()

    return result


def run_test_agent(key, test_fn):
    print(f"Running test: {key}")

    prev_argv = sys.argv
    prev_cwd = os.getcwd()
    sys.argv = [".\\agent.py ", f"{key}", ".\\target\\test\\config.ini"]
    agent.main.test_hook = test_hook
    test_hook.test_fn = test_fn
    test_hook.init_timestamp = time.time()

    result = None
    try:
        status_code = agent.main()
        assert status_code == 0, f"Main failed with status code: {status_code}"
        os.chdir(prev_cwd)
        test_fn(TestFnMode.CHECK)
    except Exception as e:
        traceback.print_exc()
        result = False
    finally:
        test_hook.test_fn = None
        os.chdir(prev_cwd)

    agent.main.test_hook = None
    sys.argv = prev_argv

    if result is None:
        print("Passed")
    else:
        print("Failed")

    return {
        "name": test_fn.__name__,
        "result": TestResult.PASSED if result is None else TestResult.FAILED,
    }


def generate_config(fields):

    exec_name = ''
    exec_dir = ''

    if os.name == 'nt':
        exec_name = 'notepad.exe'
        exec_dir = 'C:\\Windows'
    # TODO: Linux?

    return fr"""
        [global]
        poll_interval = 0.05
        exec_launch_cooloff = 0.05
        exec_dir = {exec_dir}
        exec_name = {exec_name}
        exec_setup_script =
        exec_startup_script =
        exec_poll_name =
        exec_args =
        backup_interval =
        backup_total_to_keep = 10
        backup_target_dir = {tmp_path_test_target_dir}
        backup_target_hash_dir =
        backup_dest_dir = {tmp_path_test_bkup_dir}
        test_enabled = True
        test_sample_runtime = 1
        test_kill_process_on_exit = True

        [test]
        {fields}
        """


def test_hook(op_config):
    runtime = agent.get_field_or_default(op_config, 'test_sample_runtime', 0)
    if runtime > 0 and time.time() - test_hook.init_timestamp > runtime:
        agent.signal_handler(signal.SIGINT, None)

    if agent.get_field_or_default(op_config, 'test_kill_process_on_exit', False) and agent.get_agent_state() is agent.AgentState.SHUTTING_DOWN:
        pinfo = agent.get_process_info(op_config)
        if not pinfo is None:
            os.kill(int(pinfo['pid']), signal.SIGINT)

    if not test_hook.test_fn is None:
        test_hook.test_fn(TestFnMode.TICK)


test_hook.test_fn = None


def boot_test(mode):
    if mode is TestFnMode.SETUP:
        return generate_config(fr"""
                               """)
    assert True, 'NOOP'


def backup_test_simple(mode):
    if mode is TestFnMode.SETUP:
        return generate_config(fr"""
            sample_runtime = 1
            exec_dir = C:\Windows
            exec_name = notepad.exe
            backup_interval = 0.25
            backup_total_to_keep = 1
        """)
    elif mode is TestFnMode.CHECK:
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

        assert cfg["bkups"][0]["timestamp"] - cfg["last_bkup"] < 10.0, 'The timestamp for the single backup should be close to the final backup time'


def backup_test_multiple(mode):
    if mode is TestFnMode.SETUP:
        return generate_config(fr"""
            poll_interval = 0.0
            exec_launch_cooloff = 0.0
            sample_runtime = 2
            exec_dir = C:\Windows
            exec_name = notepad.exe
            backup_interval = 0.0
            backup_total_to_keep = 3
        """)
    elif mode is TestFnMode.TICK:
        Path(f"{tmp_path_test_target_dir}/{time.time()}.txt").touch()
    elif mode is TestFnMode.CHECK:
        backup_files = os.listdir(tmp_path_test_bkup_dir)
        assert len(backup_files) == 4, 'Should have 6 files in backup directory'


def main():
    results = [
        run_test(boot_test),
        run_test(backup_test_simple),
        run_test(backup_test_multiple),
    ]

    passed = list(filter(lambda x: x['result'] == TestResult.PASSED, results))
    failed = list(filter(lambda x: x['result'] == TestResult.FAILED, results))

    print(f"Passed({len(passed)}): {passed}")
    print(f"Failed({len(failed)}): {failed}")


if __name__ == "__main__":
    main()
