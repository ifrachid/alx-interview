#!/usr/bin/python3
""" Log parsing challenge """
from datetime import datetime
from random import random, randint
from re import match
from sys import stdin
from time import sleep
from typing import Optional, Sequence, List


def taint_line(log_line: str) -> str:
    """
    taint_line(str1) -> str1 | tainted_str1

    Used to randomly invalidate/taint a log line.
    """
    # factor=12 (6 cases * 2) means that match is twice as likely to default
    factor = 12
    try:
        match randint(0, factor):
            case 1:
                # Taint IP
                return f'{log_line[log_line.find("-"):]}'
            case 2:
                # Taint date
                return ' '.join(log_line.split("]"))
            case 3:
                # Taint request string
                return ''.join(log_line.split('"'))
            case 4:
                # Taint status code
                i = log_line.rfind(' ')
                return f'{log_line[:i - 3]}CODE{log_line[i:]}'
            case 5:
                # Taint file size
                return ' '.join(log_line.split()[:-1])
            case 6:
                # Simulate an empty line
                return '\n'
            case _:
                # Leave line untainted
                return log_line
    except Exception:
        return log_line


def check_line(log_line: str, verbose: Optional[bool] = False,
               lines: Optional[int] = 1) -> Sequence[int]:
    """
    Checks line is right log format and returns two values from it:
    (status_code, file_size)

    Returns (0, 0) instead if line has any errors
    `if check_line(*kwargs)[1]` can be used to check success as
    file_size==0 on ERROR, >=1 on SUCCESS.
    """
    check = 'ip'
    try:
        # Check for valid IP address
        ip = match(r'\w.*\s*-\s*\[', log_line).span()[1]

        # Check valid date follows IP address
        check = 'date'
        date = match(r'.*]', log_line[ip:]).span()[1]
        date_str = log_line[ip: ip + date].split('.')
        valid = str(datetime.strptime(date_str[0], '%Y-%m-%d %H:%M:%S'))
        if not (date_str[0] == valid and match(r'\d*', date_str[1]).span()[1]):
            raise AttributeError('Invalid date format!')

        # Check valid request info string follows date
        check = 'req'
        req = match(' ?".*"', log_line[ip + date:]).span()[1]
        req_str = log_line[ip + date:][:req]
        if req_str[1:] != '"GET /projects/260 HTTP/1.1"':
            raise AttributeError('Invalid request string format!')

        # Check valid status code follows request string
        check = 'code'
        status = match(r' \S*', log_line[ip + date + req:-1]).span()[1]
        status_str = log_line[ip + date + req:][1:status]
        status_str = int(status_str) if status_str.isnumeric() else 0

        # Check valid file size follows status code
        check = 'size'
        size = match(r' \d*$', log_line[ip + date + req + status:]).span()[1]
        size_str = log_line[ip + date + req + status:][1:size]
        size_str = int(size_str) if size_str.isnumeric() else 0
        if 'CODE' in log_line:
            raise AttributeError('Invalid status code!')

        if verbose:
            print(f'{lines:2d}. {log_line[:-1]}')

        # Return status code and file size as all tests passed
        return status_str, size_str

    # Catch AttributeError raised when a regex match fails on log_line
    except (AttributeError, ValueError) as err:
        if verbose:
            if 'status code' in err.__str__():
                print(f'{lines:2d}. {log_line[:-1]}\t>>> code')
                return status_str, size_str
            if log_line[:-1]:
                print(f'{lines:2d}. {log_line[:-1]}\t>>> {check}')
            else:
                print(f'{lines:2d}.\t>>> BLANK ')

    # Return null values for status code and file size as a test failed
    return 0, 0


def log_parser(log_lines: Optional[List[str]] = None,
               slowmo: Optional[bool] = False, taint: Optional[bool] = False,
               verbose: Optional[bool] = False) -> None:
    """
    param log_lines: A list of new line-terminated log strings to be parsed.
                     Not providing this optional parameter switches to stdin
                     for inputs.
    param slowmo: Enables random 1-second pauses between inputs
    param taint: Randomly invalidates/taints a line before it is parsed
    param verbose: Enables printing additional info, plus errors if any.
                   Passing taint=True also enables this automatically.

    log_parser() -> None

    log_parser([log_lines[, slowmo, taint[, verbose]]]) -> None

    Reads stdin (when log_lines isn't passed) or a list (when log_lines is
    passed) line by line, computes various metrics, then prints a summary
    every ten lines and on exit. Printing extra info con be requested using
    the verbose switch.

    All the parameters are optional, and the other three are only checked if
    log_lines is provided. They are ignored otherwise.
    """
    line = ' '
    lines, status_code, file_size, i, valid = 1, 0, 0, 0, 0
    status_codes = [200, 301, 400, 401, 403, 404, 405, 500]
    summary = {'codes': {'200': 0, '301': 0, '400': 0, '401': 0, '403': 0,
                         '404': 0, '405': 0, '500': 0},
               'size': 0}
    first_run = True

    # Forces verbosity in taint mode so that tainted lines can be noted
    verbose = True if taint else verbose

    while line:
        skip, close = False, False
        try:
            # Use list for inputs if one was passed, else use standard input
            if log_lines:
                line = log_lines[i]
                i += 1
            else:
                line = stdin.readline()
                # Terminate on empty line from stdin
                if not line:
                    raise EOFError

            # Process __args__ if script's first run
            if first_run:
                first_run = False
                if main(line):
                    return

            # Pause for 1 or 0 second(s)
            if slowmo:
                sleep(random())

            # Make line invalid at random
            if taint:
                line = taint_line(line)

            # Check if line is right format and parse needed data
            status_code, file_size = check_line(line, verbose, lines)
            if not file_size:
                skip = True

        # Handle Ctrl+C, Ctrl+Z, and end of list (when log_lines is passed)
        except (KeyboardInterrupt, EOFError, IndexError):
            close = True
            break
        finally:
            if not close and not skip and file_size:
                valid += 1
                # Record file size
                summary['size'] += file_size
                if status_code in status_codes:
                    # Record status code
                    summary['codes'][str(status_code)] += 1
            if (lines and not lines % 10) or close:
                # Print current status
                if close:
                    lines -= 1
                if verbose:
                    print(f'Total logs: {lines}', end='')
                    if lines - valid:
                        print(f'\t(valid: {valid}, invalid: {lines - valid})')
                    else:
                        print()
                print(f'File size: {summary["size"]}')
                for key in sorted(summary['codes'].keys()):
                    if summary['codes'].get(key):
                        print(f'{key}: {summary["codes"][key]}')
                # if close and verbose:
            lines += 1


def use_list(slowmo: Optional[bool] = False, taint: Optional[bool] = False,
               verbose: Optional[bool] = False) -> None:
    """ Calls log_parser with a list of automatically sequenced log lines """
    from random import choice
    logs = []
    status_codes = [200, 301, 400, 401, 403, 404, 405, 500]
    base = '{:d}.{:d}.{:d}.{:d} - [{}] "GET /projects/260 HTTP/1.1" {} {}\n'
    for i in range(10000):
        logs.append(
            base.format(randint(1, 255), randint(1, 255),
                        randint(1, 255), randint(1, 255),
                        datetime.now(),
                        choice(status_codes),
                        randint(1, 1024))
        )
    log_parser(logs, slowmo, taint, verbose)


def main(args: str) -> True:
    """
    Calls log_parser() with given or no parameters.

    log_parser can be called with parameters if first line uses a special
    __ARGS__ dunder with this syntax: `__args__ <param> <param>. . .`

    param is a single keyword/argument, and all are case-insensitive for
    convenience. The valid options are,
     >> HELP:    prints this docstring. (This supersedes all others below)
     >> SLOWMO:  calls log_parser in slowmo mode -> log_parser(slowmo=True)
     >> TAINT:   calls log_parser in taint mode -> log_parser(taint=True)
     >> VERBOSE: calls log_parser in verbose mode -> log_parser(verbose=True)
     >> LIST:    calls log_parser in list mode -> log_parser(log_lines)
    SHORTHAND VERSION: Type a hyphen and first letter of the param: -S -L -h.

    e.g.: __args__ -h
          __ARGS__ Verbose -S LiSt
    """
    mode_str = []
    if args.strip() and '__args__' in args.lower().split()[0]:
        slowmo, taint, verbose = False, False, False
        args = args.lower().split()
        if 'help' in args or '-h' in args:
            print(main.__doc__)
            main()
            return
        if 'slowmo' in args or '-s' in args:
            slowmo = True
            mode_str.append('slowmo')
        if 'taint' in args or '-t' in args:
            taint = True
            mode_str.append('taint')
        if 'verbose' in args or '-v' in args:
            verbose = True
            mode_str.append('verbose')
        if 'list' in args or '-l' in args:
            if verbose:
                print(f'Running in LIST mode. . . args: {mode_str}')
            use_list(slowmo, taint, verbose)
        else:
            if verbose:
                print(f'Running in STDIN mode. . . args: {mode_str}')
            log_parser(slowmo=slowmo, taint=taint, verbose=verbose)
        return True
    else:
        return False


if __name__ == '__main__':
    """ Tests the code in this module """
    log_parser()
