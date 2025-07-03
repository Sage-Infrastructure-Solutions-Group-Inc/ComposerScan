# ComposerScan
This is very basic utility that utilizes the same APIs as `composer` to scan `php` dependencies for vulnerabilities.

The man utility `scanner.py` performs the scanning and outputs a `json` formatted file. The `formatCSV.py` is a simple 
tool to translate that `json` file into a `csv` file if that format is desired. All tools have help text that
will provide you with guidance.

## scanner.py
This utility will search for vulnerabilities based on the packages listed in the `composer.lock` file for your project.
The versioning logic in the utility _is imperfect_ and where it is unclear that a vulnerability would be applicable to
the package version range in `composer.lock` it is simply omitted. 
The following is the help text for the software:
```bash
python3 scanner.py -h
```
```text
usage: scanner.py [-h] input output

positional arguments:
  input       the input composer.lock file.
  output      the output resport file.

options:
  -h, --help  show this help message and exit

```