<h2 align="center"> Gdorker </h2>

**Overview:**
A simple Python based CLI tool for google dorking!

**Features:**
- ~Added Automation for updated proxies, thanks to [TheSpeedX](https://github.com/TheSpeedX)~
- Added Cache proxy method, time interval = 1day
- Added By default cookies, to avoid barriers while searching!
- Added List of default "Google Dorking" queries, up to 70+
- ~Added List of "User Agents" 890+~
> [!WARNING]
> Use at your Own risk : Still Upgrading...

>[!NOTE]
>I'm `mr0erek` is not responsible for any damages caused by this tool,
>The User who is using the tool will be resposible for any damages caused by this tool.

### Technologies and Libraries Used

1. **Python**: The core programming language used to write the script.

2. **Requests**: A popular Python library for making HTTP requests. It is used to send requests to the Google search engine to retrieve search results.

3. **Beautiful Soup**: A Python library for parsing HTML and XML documents. It is used to parse the HTML content of the search results retrieved from Google.

4. **contextlib**: A standard Python library module that provides utilities for working with context managers. Although it's not explicitly used in the provided code snippet, it's imported.

5. **argparse**: A standard Python library module for parsing command-line arguments. It allows for parsing command-line arguments passed to the script, although it's not used in the provided code snippet.

6. **sys**: A standard Python library module providing access to some variables used or maintained by the Python interpreter and to functions that interact strongly with the interpreter. It's imported but not explicitly used in the provided code snippet.

7. **time**: A standard Python library module providing various time-related functions. It's not explicitly used in the provided code snippet.

8. **datetime**: A standard Python library module providing classes for manipulating dates and times. It's used to handle timestamps in the script.

9. **base64**: A standard Python library module providing functions for encoding and decoding data in Base64 format. Although it's imported, it's not explicitly used in the provided code snippet.

10. **json**: A standard Python library module for encoding and decoding JSON data. It's used to work with JSON data, although it's not explicitly used in the provided code snippet.

11. **re**: A standard Python library module providing support for regular expressions. Although it's imported, it's not explicitly used in the provided code snippet.

12. **os**: A standard Python library module providing a portable way of using operating system-dependent functionality. Although it's imported, it's not explicitly used in the provided code snippet.

**Usage:**
#### Linux

> If you haven't Install python and python-pip install it by given below commands
     
     sudo apt update && apt upgrade -y; sudo apt install python3 python3-pip  

_OR_ 

> Termux Users
     
     pkg update && pkg upgrade -y; pkg i git python3 -y;    

> For Both PC and Termux users [LINUX ONLY]
```bash
cd ~/; git clone --depth=1 https://github.com/mr0erek/Gdorker; cd Gdorker; pip install -r requirements.txt
```
<hr></hr>    

> To start use command below

```shell
python Gdorker.py
```

_OR_

```shell
python3 Gdorker.py
````

**Examples: Default**
```
python Gdorker.py
```
**More, Try Help**
`python Gdorker.py -h` or `--help`
```
usage: Gdorker.py [-h] [-s SEARCH] [-d [DORK]] [-e ENGINE] [-p PAGES] [-P PROCESSES] [-sl SITELIST]                             
                                                                                                                                      
Google Dorking Tool                                                                                                                   
                                                                                                                                      
options:                                                                                                                              
  -h, --help                         : Show this help message and exit                                                                               
  -s SEARCH, --search SEARCH         : Site/Query to search                                                                                          
  -d [DORK], --dork [DORK]           : To Enable Dork Search, -d <files> for coustom Dorking.                                                        
  -e ENGINE, --engine ENGINE         : Choose your search Google/Bing                                                                                
  -p PAGES, --pages PAGES            : Specify the Number of Pages (Default: 1)                                                                      
  -P PROCESSES, --process PROCESSES  : Specify the Number of Processes (Default: 2)                                                                  
  -sl SITELIST, --site-list SITELIST : Add your Site list file
```
**Future Improvements:**

I'm working on it....


**Contributing:**

As it is Open Source feel free to contribute!
