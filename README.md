# py-agent

Python agent for running a user service. This supports automatic relaunching and automatic backup. Read the `config.sample.ini` for further details.

## Sample Usage

Consider the following `config.ini`:

`config.ini`:

```
[mspaint]
exec_dir = C:\Users\me\AppData\Local\Microsoft\WindowsApps
exec_name = mspaint.exe
exec_setup_script = sleep 2
backup_interval = 10
backup_target_dir = C:\test_server_data
backup_dest_dir = C:\Users\me
poll_interval = 3
exec_launch_cooloff = 5
```

`cmd`:
```
python py-agent.py mspaint
```

This will execute the mspaint executable with a startup action of sleeping for 2 seconds. Every 10 seconds the `C:\test_server_data` will be archived and backed up to the User's directory. `py-agent` will poll every 3 seconds to ensure that `mspaint.exe` is running, and if not, relaunch `mspaint.exe`.

A slightly modified real-world example for my 7d2d server:

```
[7d2d]
exec_dir = C:\Program Files (x86)\Steam\steamapps\common\7 Days to Die Dedicated Server
exec_poll_name = 7DaysToDieServer.exe
exec_startup_script = startdedicated.bat
exec_launch_cooloff = 30
```

## License
Under the WTFPL.