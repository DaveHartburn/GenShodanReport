# GenShodanReport
Generates a Shodan report breaking our various facets.
 - The number of exposed hosts found
 - The number of different ports/protocols found
 - A CSV list of all open IP addresses and all found open ports next to each one
 - A CSV of open ports, with a count of each port open
 - A CSV of SSL versions and the count of each
 - The subnet distribution, assuming the range included a number of class C (/24) subnets, it displays the third octet and the count

To run:
<code>
    genShodanReport.py [-q] [-l filename] -s <search>
    -q : Quiet, limited screen output
    -l : Followed by a filename, use a previously downloaded file (useful for testing)
    search : A search string. e.g. net:1.1.0.0/16, ignored if we are using a local file
      A range can be excluded, e.g. -s "net:1.1.0.0/16 -net:1.1.225.0/24"
      For multiple subnets, you can search for asn (or any other shodan search term) "asn:AS1234"
    Note, shodan commands will not execute if you have not configured your API string
 </code>

If you use a previously downloaded file, it must be the json.gz file, not the CSV file. The shodan command itself will throw errors.

Each run will create a timestamped directory in the current directory, containing three files:
 - dlData.csv   - The raw data in CSV format
 - dlData.json.gz - The raw data in gzipped JSON format
 - report.txt     - A summary text report, with CSV sections to cut and paste at will
 
Installing
 - Copy the file or 'git clone' the repository
 - Ensure you have a working python environment
 - Add the shodan command with `pip install -U --user shodan`
 - Set API key with `shodan init <apikey>`
   - The API key can be found from the account section when logging into the shodan web interface

 Shodan Install Issues
   - See https://help.shodan.io/command-line-interface/0-installation
   - Under Windows 11, I got the error "No module named -pkg_resources"
     - `pip install -U --user setuptools`
   - The shodan script was not in the path. Annoyingly the Local directories are added to the path, but scripts are added to Roaming. You may need to go hunting!
     - Run Settings and search for path
     - Select "Edit environment variables for your account" (assuming you are not an admin)
     - Add something similar to the following to your Path variable 'C:\Users\<user>\AppData\Roaming\Python\Python313\Scripts'
     - Restart your terminal

To Do:
 - Check for shodan command presence and test if API string has been entered, currently will fail ungracefully.
 - Tidy up the output on command execution, only give summary
 - Bug: Filename is based on the minute. You can not run this twice in the same minute!
