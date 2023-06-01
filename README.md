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
    Note, shodan commands will not execute if you have not configured your API string
 </code>
 
Each run will create a timestamped directory in the current directory, containing three files:
 - dlData.csv   - The raw data in CSV format
 - dlData.json.gz - The raw data in gzipped JSON format
 - report.txt     - A summary text report, with CSV sections to cut and paste at will
 
Installing
 - Copy the file or 'git clone' the repository
 - Ensure you have a working python environment
 - Add the shodan command with `pip install -U --user shodan`
 - Set API key with `shodan init <apikey>`

To Do:
 - Check for shodan command presence and test if API string has been entered, currently will fail ungracefully.
