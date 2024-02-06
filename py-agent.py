import sys
import time
import subprocess
import os
import datetime
import configparser

def read_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
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

def check_if_process_name_is_running(cfg):
    pname = cfg['exec_poll_name'] if 'exec_poll_name' in cfg else cfg['exec_name']
    processes = get_all_running_processes()
    for p in processes:
        if pname in p:
            return True

    return False

def log(msg):
    now = datetime.datetime.now()
    print("[%s] %s" % (now.strftime("%Y-%m-%d %H:%M:%S"), msg))

# Expected usage: ./python py-agent.py <config-to-execute>
# Example: python py-agent.py "mspaint"
def main():
    cfg = read_config()
    """
    for section in cfg.sections():
        log((section, dict(cfg[section])))
    """

    config_key = sys.argv[1]
    if not config_key in cfg:
        log("Config '%s' not found in config.ini" % config_key)
        exit(-1)

    op_config = get_config_to_execute(cfg, config_key)

    has_process = check_if_process_name_is_running(op_config)

    if has_process:
        log("Detected existing running process, skipping setup script")
    elif 'setup_script' in op_config:
        log("Executing setup script: %s" % op_config['setup_script'])
        os.system(op_config['setup_script'])

    log("Config selected: %s: %s" % (config_key, op_config))
    path = op_config['exec_dir']
    log("Setting execution path: %s" % path)
    os.chdir(path)

    while (True):
        log("Polling tick")
        delay = int(op_config['poll_interval'])
        if not has_process or not check_if_process_name_is_running(op_config):
            log("Starting process %s" % op_config['exec_name'])
            process = subprocess.Popen((op_config['exec_name'], op_config['exec_args']))
            delay = int(op_config['exec_launch_cooloff'])

        # TODO: Server backup

        time.sleep(delay)

if __name__ == "__main__":
    main()
