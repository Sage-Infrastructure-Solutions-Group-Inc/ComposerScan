# ComposerScan
This is very basic utility that utilizes the same APIs as `composer` to scan `php` dependencies for vulnerabilities.

The man utility `scanner.py` performs the scanning and outputs a `json` formatted file. The `formatCSV.py` is a simple 
tool to translate that `json` file into a `csv` file if that format is desired. All tools have help text that
will provide with guidance.
