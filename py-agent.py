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

class Logger(object):
    prefix = None

    def __init__(self, prefix):
        self.prefix = prefix

    def log(self, msg):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{self.prefix}][{timestamp}] {msg}")

# Expected usage: ./python py-agent.py <config-to-execute> [config-file]
# Example: python py-agent.py "mspaint"
# Example: python py-agent.py "mspaint" config.ini
def main():
    logger = Logger(None)
    target_config = None
    config_path = 'config.ini'
    if not len(sys.argv) in [2, 3]:
        logger.log("Expected usage: ./python py-agent.py <config-to-execute> [config-file]")
        exit(-1)

    if len(sys.argv) == 3:
        config_path = sys.argv[2]

    if not os.path.isfile(config_path):
        logger.log(f"Failed to find config file: {config_path}. Please either target a config file or create 'config.ini' at the root.")
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
    for key, value in op_config.items():
        logger.log(f"\t[{key}] => {value}")

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

    while (True):
        logger.log(f"Polling tick [{get_additional_process_info(op_config, backup_timestamp)}]")
        delay = int(op_config['poll_interval'])
        if not has_process or not is_process_running(op_config):
            logger.log(f"Starting process {op_config['exec_name']}")
            if len(op_config['exec_name']) > 0:
                subprocess.Popen((op_config['exec_name'], op_config['exec_args']))
            elif len(op_config['exec_startup_script']) > 0:
                subprocess.Popen(op_config['exec_startup_script'])
            else:
                logger.log("Failed to startup process as we don't have a exec_name or exec_startup_script")
                exit(-1)

            delay = max(int(op_config['exec_launch_cooloff']), delay)
            backup_timestamp = time.time()
            has_process = True
        elif has_backup and time.time() - backup_timestamp >= float(op_config['backup_interval']):
            perform_backup(logger, op_config)
            backup_timestamp = time.time()

        time.sleep(delay)

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

    return ", ".join(map(lambda i: f"{i[0]}: {i[1]}", result.items()))

def perform_backup(logger, op_config):
    bkup_file_name = bkup_file_name_for_config(op_config)
    cfg = read_bkup_config(bkup_file_name)
    now = datetime.datetime.now()
    date_str = slugify(now.strftime("%Y-%m-%d_%H-%M-%S"))
    backup_name = f"{get_process_name_for_config(op_config)}.{date_str}"
    logger.log(f"Performing backup '{backup_name}'")
    cfg["bkups"].append({ "name": backup_name, "timestamp": time.time() })
    cfg["last_bkup"] = time.time()
    shutil.make_archive(f"{op_config['backup_dest_dir']}/{backup_name}", 'zip', op_config['backup_target_dir'])
    cfg = prune_backups(op_config, cfg, logger)
    write_bkup_config(bkup_file_name, cfg)
    logger.log("Done!")

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
    bkup_file_name = f"py-agent-bkup-manifest.{slugify(pname)}.json"
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
        if pname_to_consider in p["raw"]:
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

if __name__ == "__main__":
    main()
