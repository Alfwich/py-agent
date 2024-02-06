import sys
import time
import subprocess
import os
import datetime
import configparser

# Expected usage: ./python py-agent.py <config-to-execute> [config-file]
# Example: python py-agent.py "mspaint"
# Example: python py-agent.py "mspaint" config.ini
def main():
    config_path = 'config.sample.ini'
    if not len(sys.argv) in [2, 3]:
        log("Expected usage: ./python py-agent.py <config-to-execute> [config-file]")
        exit(-1)

    config_key = sys.argv[1]

    if len(sys.argv) == 3:
        config_path = sys.argv[2]

    cfg = read_config(config_path)

    if not config_key in cfg:
        log("Config '%s' not found in %s" % (config_key, config_path))
        exit(-1)

    op_config = get_config_to_execute(cfg, config_key)

    has_process = is_process_running(op_config)

    if has_process:
        log("Detected existing running process, skipping setup script")
    elif len(op_config['exec_setup_script']) > 0:
        log("Executing setup script: %s" % op_config['exec_setup_script'])
        p = subprocess.Popen(op_config['exec_setup_script'])
        p.wait()

    log("Config selected: %s: %s" % (config_key, op_config))
    path = op_config['exec_dir']
    log("Setting execution path: %s" % path)
    os.chdir(path)

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

            delay = int(op_config['exec_launch_cooloff'])
            has_process = True

        # TODO: Server backup

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

def is_process_running(cfg):
    pname_to_consider = cfg['exec_poll_name'] if ('exec_poll_name' in cfg and len(cfg['exec_poll_name']) > 0) else cfg['exec_name']
    processes = get_all_running_processes()

    for p in processes:
        if pname_to_consider in p:
            return True

    return False

def log(msg):
    now = datetime.datetime.now()
    print("[%s] %s" % (now.strftime("%Y-%m-%d %H:%M:%S"), msg))

if __name__ == "__main__":
    main()
