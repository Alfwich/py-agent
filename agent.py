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


class AgentState:
    UNKNOWN, SETUP, RUNNING, SHUTTING_DOWN, FINISHED = range(5)


class AgentConfig(Enum):
    POLL_INTERVAL = 'poll_interval'
    EXEC_LAUNCH_COOLOFF = 'exec_launch_cooloff'
    EXEC_DIR = 'exec_dir'
    EXEC_NAME = 'exec_name'
    EXEC_SETUP_SCRIPT = 'exec_setup_script'
    EXEC_STARTUP_SCRIPT = 'exec_startup_script'
    EXEC_POLL_NAME = 'exec_poll_name'
    EXEC_ARGS = 'exec_args'
    BACKUP_INTERVAL = 'backup_interval'
    BACKUP_TOTAL_TO_KEEP = 'backup_total_to_keep'
    BACKUP_TARGET_DIR = 'backup_target_dir'
    BACKUP_TARGET_HASH_DIR = 'backup_target_hash_dir'
    BACKUP_DEST_DIR = 'backup_dest_dir'


class Logger(object):
    indent = 0
    prefix = None

    def __init__(self, prefix):
        self.prefix = prefix

    def log(self, msg):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{self.prefix}][{timestamp}] {'  ' * self.indent}{msg}")

    def push_indent(self):
        self.indent += 1

    def pop_indent(self):
        self.indent = self.indent - 1 if self.indent == 1 else 0


def set_agent_state(new_state):
    main.agent_state = new_state


def get_agent_state():
    return main.agent_state


def signal_handler(sig, frame):

    # The only case where we do a soft-shutdown is when the agent is running.
    if get_agent_state() is AgentState.RUNNING:
        # Perform an explicit backup and signal to the agent to terminate operations
        main.logger.log(f"Shutting down agent... Ctrl+C again to force quit")
        set_agent_state(AgentState.SHUTTING_DOWN)
    # Provide a hatch to let the user explicitly terminate the process
    else:
        sys.exit(0)

# Expected usage: ./python py-agent.py <config-to-execute> [config-file]
# Example: python py-agent.py "mspaint"
# Example: python py-agent.py "mspaint" config.ini


def main():

    logger = main.logger

    signal.signal(signal.SIGINT, signal_handler)

    set_agent_state(AgentState.SETUP)

    target_config = None
    config_path = 'config.ini'
    if not len(sys.argv) in [2, 3]:
        logger.log(
            "Expected usage: ./python py-agent.py <config-to-execute> [config-file]")
        exit(-1)

    if len(sys.argv) == 3:
        config_path = sys.argv[2]

    if not os.path.isfile(config_path):
        logger.log(f"Failed to find config file: {config_path}")
        logger.log(
            "Please either target a config file or create 'config.ini' at the root.")
        logger.log(
            "Expected usage: ./python py-agent.py <config-to-execute> [config-file]")
        exit(-1)

    cfg = read_config(config_path)

    available_configs = list(
        filter(lambda x: x != 'DEFAULT' and x != 'global', cfg.keys()))
    logger.log(f"Available configs: {available_configs}")

    target_config = sys.argv[1]

    logger = main.logger = Logger(target_config)

    if not target_config in cfg:
        logger.log(f"Config '{target_config}' not found in {config_path}")
        exit(-1)

    op_config = main.op_config = get_config_to_execute(cfg, target_config)

    has_process = is_process_running(op_config)

    logger.log(f"Config selected '{target_config}':")
    logger.push_indent()
    for key, value in op_config.items():
        logger.log(f"[{key}] => {value}")
    logger.pop_indent()

    set_title(f"[{target_config}] py-agent")

    if has_process:
        logger.log("Detected existing running process, skipping setup script")
    elif has_fields(op_config, AgentConfig.EXEC_STARTUP_SCRIPT):
        startup_script_dir = get_field(op_config, AgentConfig.EXEC_STARTUP_SCRIPT)
        logger.log(f"Executing setup script: {startup_script_dir}")
        p = subprocess.Popen(startup_script_dir)
        p.wait()

    if not has_fields(op_config, AgentConfig.EXEC_DIR):
        logger.log("'exec_dir' is required for agent operation")
        exit(-1)

    exec_name = get_field(op_config, AgentConfig.EXEC_NAME)
    exec_args = get_field(op_config, AgentConfig.EXEC_ARGS)
    exec_startup_script = get_field(op_config, AgentConfig.EXEC_STARTUP_SCRIPT)
    exec_dir = get_field(op_config, AgentConfig.EXEC_DIR)
    assert len(exec_dir) > 0, 'exec_dir is required in config'
    logger.log(f"Setting execution path: {exec_dir}")
    os.chdir(exec_dir)

    has_backup = has_fields(op_config, AgentConfig.BACKUP_INTERVAL, AgentConfig.BACKUP_DEST_DIR, AgentConfig.BACKUP_TARGET_DIR)
    backup_timestamp = 0
    if has_backup:
        bkup_file_name = bkup_file_name_for_config(op_config)
        bkup_cfg = read_bkup_config(bkup_file_name)
        if 'last_bkup' in bkup_cfg:
            backup_timestamp = bkup_cfg['last_bkup']

    set_agent_state(AgentState.RUNNING)

    while get_agent_state() is AgentState.RUNNING:

        # Hook for automated testing instrumentation
        if not main.test_hook is None:
            main.test_hook(op_config)

        if not get_agent_state() is AgentState.RUNNING:
            break

        info = get_additional_process_info(op_config, backup_timestamp)
        logger.log(f"Polling tick {info}")
        delay = get_field(op_config, AgentConfig.POLL_INTERVAL, float)
        if not has_process or not is_process_running(op_config):
            logger.log(f"Starting process {exec_name}")
            if len(exec_name) > 0:
                subprocess.Popen((exec_name, exec_args))
            elif len(exec_startup_script) > 0:
                subprocess.Popen(exec_startup_script)
            else:
                logger.log(
                    "Failed to startup process as we don't have a exec_name or exec_startup_script")
                exit(-1)

            delay = max(get_field(op_config, AgentConfig.EXEC_LAUNCH_COOLOFF, float), delay)
            backup_timestamp = time.time()
            has_process = True
        elif has_backup and time.time() - backup_timestamp >= get_field(op_config, AgentConfig.BACKUP_INTERVAL, float):
            perform_backup(logger, op_config)
            backup_timestamp = time.time()

        time.sleep(delay)

    # Do an explicit backup before terminating the agent process
    if has_backup:
        logger.log("Performing shutdown backup save")
        perform_backup(logger, op_config)

    set_agent_state(AgentState.FINISHED)


main.agent_state = AgentState.UNKNOWN
main.logger = Logger(None)
main.op_config = None
main.test_hook = None


def get_field_or_default(cfg, field_name, default):
    t = type(default)
    return t(cfg[field_name]) if (field_name in cfg and len(cfg[field_name]) > 0) else default


def get_field(cfg, field_enum, t=str):
    field_key = field_enum.value

    if field_key in cfg and len(cfg[field_key]) > 0:
        return t(cfg[field_key])

    return t()


def has_fields(cfg, *args):
    for v in args:
        if len(get_field(cfg, v)) == 0:
            return False

    return True


def get_additional_process_info(op_config, backup_timestamp):
    result = {}
    pinfo = get_process_info(op_config)
    has_backup = has_fields(op_config, AgentConfig.BACKUP_INTERVAL, AgentConfig.BACKUP_DEST_DIR, AgentConfig.BACKUP_TARGET_DIR)
    if not pinfo is None:
        working_set_size_mib = int(pinfo["working_set_size"]) / 1024 / 1024
        working_set_size = f"{working_set_size_mib:.2f}MiB"
        result["WSS"] = working_set_size
        result["pid"] = pinfo["pid"]
        if has_backup:
            time_till_next_backup_seconds = 0 if not has_backup else get_field(op_config, AgentConfig.BACKUP_INTERVAL, float) - (time.time() - backup_timestamp)

            label = "NOW"
            if time_till_next_backup_seconds > 0:
                label = f"{time_till_next_backup_seconds:.2f}s"

            result["bkup_in"] = f"{label}"

    if result:
        inner = ", ".join(map(lambda i: f"{i[0]}: {i[1]}", result.items()))
        return f"[{inner}]"
    else:
        return ""


def perform_backup(logger, op_config):
    bkup_file_name = bkup_file_name_for_config(op_config)
    cfg = read_bkup_config(bkup_file_name)
    now = datetime.datetime.now()
    date_str = slugify(now.strftime("%Y-%m-%d_%H-%M-%S"))
    backup_name = f"{get_process_name_for_config(op_config)}.{date_str}"
    logger.log(f"Performing backup '{backup_name}'")
    logger.push_indent()

    consider_hash = None
    backup_dest_dir = get_field(op_config, AgentConfig.BACKUP_DEST_DIR)
    bkup_tmp_dir = f"{backup_dest_dir}/tmp"
    bkup_tmp_name = f"{bkup_tmp_dir}/{backup_name}"

    while True:
        if os.path.exists(bkup_tmp_dir):
            shutil.rmtree(bkup_tmp_dir)

        os.makedirs(bkup_tmp_name)

        backup_target_dir = get_field(op_config, AgentConfig.BACKUP_TARGET_DIR)
        whole_bkup_hash = calc_md5_for_dir(backup_target_dir)
        consider_dir = get_field_or_default(op_config, AgentConfig.BACKUP_TARGET_HASH_DIR.value, backup_target_dir)
        consider_hash = calc_md5_for_dir(consider_dir)
        shutil.copytree(backup_target_dir, bkup_tmp_name, dirs_exist_ok=True)

        # Ensure the tmp bkup dir, target dir, and previous target dir all are the same contents
        if whole_bkup_hash == calc_md5_for_dir(backup_target_dir) == calc_md5_for_dir(bkup_tmp_name):
            break
        else:
            # Small delay to prevent being in a hot loop of constant file IO
            time.sleep(0.1)

    last_config_hash = get_field_or_default(cfg, 'last_bkup_hash', '')
    if not consider_hash == last_config_hash:
        backup_dest_dir = get_field(op_config, AgentConfig.BACKUP_DEST_DIR)
        archive_name = f"{backup_dest_dir}/{backup_name}"
        shutil.make_archive(archive_name, 'zip', bkup_tmp_name)
        cfg['bkups'].append(
            {"name": backup_name, "timestamp": time.time(), "bkup_hash": consider_hash})
        cfg['last_bkup_hash'] = consider_hash
        cfg = prune_backups(op_config, cfg, logger)
        logger.log(f"Backup written to disk hash: {consider_hash}")
    else:
        logger.log("Not backing up as backup directory has not changed")

    shutil.rmtree(bkup_tmp_dir)

    cfg['last_bkup'] = time.time()
    write_bkup_config(bkup_file_name, cfg)

    logger.log('Done!')
    logger.pop_indent()


def prune_backups(op_config, cfg, logger):
    total_bkups_to_keep = get_field(op_config, AgentConfig.BACKUP_TOTAL_TO_KEEP, int)
    if len(cfg["bkups"]) > total_bkups_to_keep:
        logger.log("Pruning backups")
        cfg["bkups"].sort(key=lambda e: e['timestamp'])

        while len(cfg["bkups"]) > total_bkups_to_keep:
            backup_dest_dir = get_field(op_config, AgentConfig.BACKUP_DEST_DIR)
            bkup_name_to_delete = cfg["bkups"].pop(0)["name"]
            bkup_file_to_delete = f"{backup_dest_dir}/{bkup_name_to_delete}.zip"
            logger.log(f"Removing {bkup_name_to_delete}")
            if os.path.isfile(bkup_file_to_delete):
                os.remove(bkup_file_to_delete)

    return cfg


def bkup_file_name_for_config(op_config):
    path = get_field(op_config, AgentConfig.BACKUP_DEST_DIR)
    pname = get_process_name_for_config(op_config)
    bkup_file_name = f"bkup-manifest.{slugify(pname)}.json"
    return f"{path}/{bkup_file_name}"


def read_bkup_config(path):
    result = {"version": 0, "bkups": [], "last_bkup": 0}

    if os.path.isfile(path):
        with open(path) as f:
            result = json.loads(f.read())

    return result


def write_bkup_config(path, cfg):
    json_data = json.dumps(cfg)
    if len(json_data) > 0:
        with open(path, "w") as f:
            f.write(json_data)


def read_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)
    return config


def get_config_to_execute(cfg, config_key):
    result = dict()

    if 'global' in cfg:
        result.update(dict(cfg['global']))

    result.update(dict(cfg[config_key]))

    return result


def get_all_running_processes():
    if os.name == 'nt':
        def at_or_default(d, i): return d[i] if len(d) > i else ""
        d = str(subprocess.check_output(['wmic', 'process', 'list', 'brief']))
        infos = list(map(lambda x: x.replace("\\r", ""), d.split("\\r\\r\\n")))
        infos = list(map(lambda x: x.split(" "), infos))
        # HandleCount, Name, Priority, ProcessId, ThreadCount, WorkingSetSize
        results = []
        for i in infos:
            entry = list(filter(lambda x: x, i))

            # Only care about valid entries
            results.append({
                "raw": "".join(i),
                "handle_count": at_or_default(entry, 0),
                "name": at_or_default(entry, 1),
                "priority": at_or_default(entry, 2),
                "pid": at_or_default(entry, 3),
                "thread_count": at_or_default(entry, 4),
                "working_set_size": at_or_default(entry, 5),
            })

        return results
    else:
        # TODO: Linux?
        return []


def set_title(title):
    if os.name == 'nt':
        os.system(f"title {title}")
    else:
        # TODO: Linux?
        pass


def get_process_name_for_config(cfg):
    return cfg['exec_poll_name'] if ('exec_poll_name' in cfg and len(cfg['exec_poll_name']) > 0) else cfg['exec_name']


def get_process_info(cfg):
    pname_to_consider = get_process_name_for_config(cfg)
    processes = get_all_running_processes()

    for p in processes:
        if pname_to_consider.lower() in p["raw"].lower():
            return p

    return None


def is_process_running(cfg):
    return False if get_process_info(cfg) is None else True


# https://stackoverflow.com/questions/295135/turn-a-string-into-a-valid-filename
def slugify(value, allow_unicode=False):
    """
    Taken from https://github.com/django/django/blob/master/django/utils/text.py
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize('NFKC', value)
    else:
        value = unicodedata.normalize('NFKD', value).encode(
            'ascii', 'ignore').decode('ascii')
    value = re.sub(r'[^\w\s-]', '', value.lower())
    return re.sub(r'[-\s]+', '-', value).strip('-_')


def calc_md5_for_dir(directory):
    def md5_update_from_dir(directory, hash):
        assert Path(directory).is_dir()
        for path in sorted(Path(directory).iterdir(), key=lambda p: str(p).lower()):
            hash.update(path.name.encode())
            if path.is_file():
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash.update(chunk)
            elif path.is_dir():
                hash = md5_update_from_dir(path, hash)
        return hash

    return md5_update_from_dir(directory, hashlib.md5()).hexdigest()


if __name__ == "__main__":
    main()
