# ___0x03.Log Parsing___
This folder contains the actual results of completing the tasks in the project ___0x03: LOG PARSING.___ The project was a technical interview exercise on **_parsing application logs_**, which is a great skill for DevOps, API development, and different forms of troubleshooting.

## Technologies Used
1. Python

## Usage
Log lines can be inputted manually or automatically from a terminal.

 1. **Automated**: Pipe in input from another app,
   `./0-generator.py | ./0-stats.py`

 2. **Manual**: Run the script from a terminal and input lines manually, `./0-stats.py`


## Mandatory Tasks
There is just one task in this project, which is a Python script (*.py) named [0-stats.py](0-stats.py).

## Advanced Tasks
There is none in this project, but I went out on a limb and created an advanced version of the log parser named [0-stats_advanced.py](0-stats_advanced.py).

### Usage (Optional Features)
The above stated usage for the standard version also apply here, with the following additions:
* **As a function**:
Import _log_parser()_ from [0-stats_advanced.py](0-stats_advanced.py), then pass a list to it with the lines:
      `log_parser(log_lines)`
* **Run with parameters**:
The log parser supports the following features/parameters:
  * **_slowmo_**: Enables random 1-second pauses between inputs
  * **_taint_**: Randomly invalidates/taints a line before it is parsed
  * **_verbose_**: Enables printing additional info, plus errors if any.

    _Passing taint=True also enables this automatically._

  Any/all of these can be activated by,
  * **As a function**: Call the log_parser function with the required parameter(s) as True. e.g.,

        log_parser(slowmo=True, taint=True, verbose=True)
        log_parser(log_lines, verbose=True)
  * **From the terminal**: First log line must use a special \_\_ARGS__ dunder with this syntax: `__args__ <param> <param>. . .`, else script skips checking for parameters and parses the line normally. **Usage**:

        __args__ -h                # print usage documentation
        __ARGS__ Verbose -S LiSt   # enable verbose, slowmo, list modes
