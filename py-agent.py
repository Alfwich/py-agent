import sys
import time
import subprocess
import os
import datetime
import configparser
import shutil
import unicodedata
import re

# Expected usage: ./python py-agent.py <config-to-execute> [config-file]
# Example: python py-agent.py "mspaint"
# Example: python py-agent.py "mspaint" config.ini
def main():
    config_path = 'config.ini'
    if not len(sys.argv) in [2, 3]:
        log("Expected usage: ./python py-agent.py <config-to-execute> [config-file]")
        exit(-1)

    config_key = sys.argv[1]

    if len(sys.argv) == 3:
        config_path = sys.argv[2]

    if not os.path.isfile(config_path):
        log("Failed to find config file: %s. Please either target a config file or create 'config.ini' at the root." % config_path)
        exit(-1)

    cfg = read_config(config_path)

    if not config_key in cfg:
        log("Config '%s' not found in %s" % (config_key, config_path))
        exit(-1)

    op_config = get_config_to_execute(cfg, config_key)

    has_process = is_process_running(op_config)

    available_configs = list(filter(lambda x: x != 'DEFAULT' and x != 'global', cfg.keys()))
    log(f"Available configs: {available_configs}")
    log("Config selected '%s':" % config_key)
    for key, value in op_config.items():
        log("\t[%s] => %s" % (key, value))

    if has_process:
        log("Detected existing running process, skipping setup script")
    elif len(op_config['exec_setup_script']) > 0:
        log("Executing setup script: %s" % op_config['exec_setup_script'])
        p = subprocess.Popen(op_config['exec_setup_script'])
        p.wait()

    log("Setting execution path: %s" % op_config['exec_dir'])
    os.chdir(op_config['exec_dir'])

    backup_timestamp = time.time()
    while (True):
        log("Polling tick")
        delay = int(op_config['poll_interval'])
        if not has_process or not is_process_running(op_config):
            log("Starting process %s" % op_config['exec_name'])
            if len(op_config['exec_name']) > 0:
                subprocess.Popen((op_config['exec_name'], op_config['exec_args']))
            elif len(op_config['exec_startup_script']) > 0:
                subprocess.Popen(op_config['exec_startup_script'])
            else:
                log("Failed to startup process as we don't have a exec_name or exec_startup_script")
                exit(-1)

            delay = max(int(op_config['exec_launch_cooloff']), delay)
            backup_timestamp = time.time()
            has_process = True
        elif time.time() - backup_timestamp >= float(op_config['backup_interval']):

            now = datetime.datetime.now()
            date_str = slugify(now.strftime("%Y-%m-%d_%H-%M-%S"))
            backup_name = "%s.%s" % (get_process_name_for_config(op_config), date_str)
            log("Performing server backup '%s' ..." % (backup_name))
            shutil.make_archive("%s/%s" % (op_config['backup_dest_dir'], backup_name), 'zip', op_config['backup_target_dir'])
            backup_timestamp = time.time()
            log("Done!")

        time.sleep(delay)

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
        d = str(subprocess.check_output(['wmic', 'process', 'list', 'brief']))
        return list(map(lambda x: x.replace("\\r", "").replace(" ", "").replace("\\t", ""), d.split("\\r\\r\\n")))
    else:
        # TODO: Linux?
        return []

def get_process_name_for_config(cfg):
    return cfg['exec_poll_name'] if ('exec_poll_name' in cfg and len(cfg['exec_poll_name']) > 0) else cfg['exec_name']

def is_process_running(cfg):
    pname_to_consider = get_process_name_for_config(cfg)
    processes = get_all_running_processes()

    for p in processes:
        if pname_to_consider in p:
            return True

    return False

def log(msg):
    now = datetime.datetime.now()
    print("[%s] %s" % (now.strftime("%Y-%m-%d %H:%M:%S"), msg))

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
