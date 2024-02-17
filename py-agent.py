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

class AgentState(Enum):
    UNKNOWN = 0
    SETUP = 1
    RUNNING = 2
    SHUTTING_DOWN = 4
    FINISHED = 5

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

agent_state = AgentState.UNKNOWN
def set_agent_state(new_state):
    global agent_state
    agent_state = new_state

def get_agent_state():
    global agent_state
    return agent_state

# Share these concepts with the signal_handler
logger = Logger(None)
op_config = None
def signal_handler(sig, frame):

    # The only case where we do a soft-shutdown is when the agent is running.
    if get_agent_state() is AgentState.RUNNING:
        # Perform an explicit backup and signal to the agent to terminate operations
        logger.log(f"Shutting down agent... Ctrl+C again to force quit")
        set_agent_state(AgentState.SHUTTING_DOWN)
    # Provide a hatch to let the user explicitly terminate the process
    else: 
        sys.exit(0)

# Expected usage: ./python py-agent.py <config-to-execute> [config-file]
# Example: python py-agent.py "mspaint"
# Example: python py-agent.py "mspaint" config.ini
def main():

    global logger
    global op_config

    signal.signal(signal.SIGINT, signal_handler)

    set_agent_state(AgentState.SETUP)

    target_config = None
    config_path = 'config.ini'
    if not len(sys.argv) in [2, 3]:
        logger.log("Expected usage: ./python py-agent.py <config-to-execute> [config-file]")
        exit(-1)

    if len(sys.argv) == 3:
        config_path = sys.argv[2]

    if not os.path.isfile(config_path):
        logger.log(f"Failed to find config file: {config_path}. Please either target a config file or create 'config.ini' at the root.")
        logger.log("Expected usage: ./python py-agent.py <config-to-execute> [config-file]")
        exit(-1)

    cfg = read_config(config_path)

    available_configs = list(filter(lambda x: x != 'DEFAULT' and x != 'global', cfg.keys()))
    logger.log(f"Available configs: {available_configs}")

    target_config = sys.argv[1]

    logger = Logger(target_config)

    if not target_config in cfg:
        logger.log(f"Config '{target_config}' not found in {config_path}")
        exit(-1)

    op_config = get_config_to_execute(cfg, target_config)

    has_process = is_process_running(op_config)

    logger.log(f"Config selected '{target_config}':")
    logger.push_indent()
    for key, value in op_config.items():
        logger.log(f"[{key}] => {value}")
    logger.pop_indent()

    set_title(f"[{target_config}] py-agent")

    if has_process:
        logger.log("Detected existing running process, skipping setup script")
    elif len(op_config['exec_setup_script']) > 0:
        logger.log(f"Executing setup script: {op_config['exec_setup_script']}")
        p = subprocess.Popen(op_config['exec_setup_script'])
        p.wait()

    logger.log(f"Setting execution path: {op_config['exec_dir']}")
    os.chdir(op_config['exec_dir'])

    has_backup = len(op_config['backup_interval']) > 0 and len(op_config["backup_dest_dir"]) > 0 and len(op_config["backup_target_dir"]) > 0
    backup_timestamp = 0
    if has_backup:
        bkup_file_name = bkup_file_name_for_config(op_config)
        bkup_cfg = read_bkup_config(bkup_file_name)
        if 'last_bkup' in bkup_cfg:
            backup_timestamp = bkup_cfg['last_bkup'] 

    set_agent_state(AgentState.RUNNING)

    while get_agent_state() is AgentState.RUNNING:
        # Hook for automated testing instrumentation 
        test_hook(op_config)

        if not get_agent_state() is AgentState.RUNNING:
            break

        logger.log(f"Polling tick {get_additional_process_info(op_config, backup_timestamp)}")
        delay = float(op_config['poll_interval'])
        if not has_process or not is_process_running(op_config):
            logger.log(f"Starting process {op_config['exec_name']}")
            if len(op_config['exec_name']) > 0:
                subprocess.Popen((op_config['exec_name'], op_config['exec_args']))
            elif len(op_config['exec_startup_script']) > 0:
                subprocess.Popen(op_config['exec_startup_script'])
            else:
                logger.log("Failed to startup process as we don't have a exec_name or exec_startup_script")
                exit(-1)

            delay = max(float(op_config['exec_launch_cooloff']), delay)
            backup_timestamp = time.time()
            has_process = True
        elif has_backup and time.time() - backup_timestamp >= float(op_config['backup_interval']):
            perform_backup(logger, op_config)
            backup_timestamp = time.time()

        time.sleep(delay)


    # Do an explicit backup before terminating the agent process
    if has_backup:
        logger.log("Performing shutdown backup save")
        perform_backup(logger, op_config)


    set_agent_state(AgentState.FINISHED)

def get_additional_process_info(op_config, backup_timestamp):
    result = {}
    pinfo = get_process_info(op_config)
    has_backup = len(op_config['backup_interval']) > 0 and len(op_config["backup_dest_dir"]) > 0 and len(op_config["backup_target_dir"]) > 0
    if not pinfo is None:
        working_set_size_mib = int(pinfo["working_set_size"]) / 1024 / 1024
        working_set_size = f"{working_set_size_mib:.2f}MiB"
        result["WSS"] = working_set_size
        result["pid"] = pinfo["pid"]
        if has_backup:
            time_till_next_backup_seconds = 0 if not has_backup else float(op_config['backup_interval']) - (time.time() - backup_timestamp) 
            result["bkup_in"] = f"{time_till_next_backup_seconds:.2f}s" if time_till_next_backup_seconds > 0 else "NOW"

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
    bkup_tmp_dir = f"{op_config['backup_dest_dir']}/tmp"
    bkup_tmp_name = f"{bkup_tmp_dir}/{backup_name}"

    while True:
        if os.path.exists(bkup_tmp_dir):
            shutil.rmtree(bkup_tmp_dir)

        os.makedirs(bkup_tmp_name)

        whole_bkup_hash = calc_md5_for_dir(op_config['backup_target_dir'])
        consider_hash = calc_md5_for_dir(op_config['backup_target_hash_dir'] if ('backup_target_hash_dir' in op_config and len(op_config['backup_target_hash_dir'])) else op_config['backup_target_dir'])
        shutil.copytree(op_config['backup_target_dir'], bkup_tmp_name, dirs_exist_ok=True)

        # Check to ensure that the tmp copy is the same as the existing files on-disk by rehashing
        # the target directory a second time after the copy. If the hashs don't match then we need to 
        # recopy the files as they might have changed while the agent was making the tmp copy.
        if whole_bkup_hash == calc_md5_for_dir(op_config['backup_target_dir']):
            break

    if not 'last_bkup_hash' in cfg or not consider_hash == cfg['last_bkup_hash']:
        archive_name = f"{op_config['backup_dest_dir']}/{backup_name}"
        shutil.make_archive(archive_name, 'zip', bkup_tmp_name)
        cfg['bkups'].append({ "name": backup_name, "timestamp": time.time(), "bkup_hash": consider_hash})
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
    total_bkups_to_keep = int(op_config["backup_total_to_keep"])
    if len(cfg["bkups"]) > total_bkups_to_keep:
        logger.log("Pruning backups")
        cfg["bkups"].sort(key=lambda e: e['timestamp'])

        while len(cfg["bkups"]) > total_bkups_to_keep:
            bkup_name_to_delete = cfg["bkups"].pop(0)["name"]
            bkup_file_to_delete = f"{op_config['backup_dest_dir']}/{bkup_name_to_delete}.zip"
            logger.log(f"Removing {bkup_name_to_delete}")
            if os.path.isfile(bkup_file_to_delete):
                os.remove(bkup_file_to_delete)

    return cfg

def bkup_file_name_for_config(op_config):
    path = op_config['backup_dest_dir']
    pname = get_process_name_for_config(op_config)
    bkup_file_name = f"bkup-manifest.{slugify(pname)}.json"
    return f"{path}/{bkup_file_name}"

def read_bkup_config(path):
    result = { "version": 0, "bkups": [] , "last_bkup": 0 }

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
        at_or_default = lambda d, i: d[i] if len(d) > i else ""
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
        value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
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

def test_hook(op_config):
    if not test_hook.init is True:
        test_hook.init_timestamp = time.time()
        test_hook.init = True
        test_hook.runtime = int(op_config['sample_runtime']) if ('sample_runtime' in op_config and op_config['sample_runtime'].isnumeric()) else None

    if not test_hook.runtime is None and time.time() - test_hook.init_timestamp > test_hook.runtime:
        signal_handler(signal.SIGINT, None)

    if 'kill_process_on_exit' in op_config and bool(op_config['kill_process_on_exit']) and get_agent_state() is AgentState.SHUTTING_DOWN:
        pinfo = get_process_info(op_config)
        if not pinfo is None:
            os.kill(int(pinfo['pid']), signal.SIGINT)

test_hook.init = False

if __name__ == "__main__":
    main()