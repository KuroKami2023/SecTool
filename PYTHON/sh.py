from flask import Flask, render_template, request, send_file
import requests
import time
import socket
from datetime import datetime
import pytz
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
from PIL import Image

app = Flask(__name__, template_folder='../HTML')

def convert_to_pht(gmt_date_str):
    if gmt_date_str == 'N/A':
        return gmt_date_str
    try:
        # Parse the GMT date string
        gmt_date = datetime.strptime(gmt_date_str, '%a, %d %b %Y %H:%M:%S GMT')
        # Define PHT timezone
        pht = pytz.timezone('Asia/Manila')
        # Convert GMT to PHT
        gmt_date = gmt_date.replace(tzinfo=pytz.utc)
        pht_date = gmt_date.astimezone(pht)
        # Format the PHT date string
        return pht_date.strftime('%a, %d %b %Y %H:%M:%S PHT')
    except ValueError:
        return gmt_date_str

def evaluate_security_headers(url):
    recommended_headers = {
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '0',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none';",
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
        'Permissions-Policy': "geolocation=(), camera=(), microphone=()",
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Resource-Policy': 'same-site',
        'Set-Cookie': None
    }

    missing_descriptions = {
        'X-XSS-Protection': "Prevents reflected XSS attacks by stopping pages from loading.",
        'Referrer-Policy': "Controls how much referrer information should be included with requests.",
        'Content-Security-Policy': "Helps to detect and mitigate certain types of attacks, including XSS.",
        'Strict-Transport-Security': "Ensures that the website is only accessible via HTTPS.",
        'Permissions-Policy': "Controls which origins can use certain browser features.",
        'Set-Cookie': "Should be configured with security attributes like HttpOnly and Secure."
    }

    recommendations = {
        'X-Frame-Options': 'X-Frame-Options: DENY',
        'X-XSS-Protection': 'X-XSS-Protection: 0',
        'X-Content-Type-Options': 'X-Content-Type-Options: nosniff',
        'Referrer-Policy': 'Referrer-Policy: strict-origin-when-cross-origin',
        'Content-Security-Policy': 'Content-Type: text/html; charset=UTF-8',
        'Strict-Transport-Security': 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
        'Permissions-Policy': 'Permissions-Policy: geolocation=(), camera=(), microphone=()',
        'Cross-Origin-Opener-Policy': 'HTTP Cross-Origin-Opener-Policy: same-origin',
        'Cross-Origin-Embedder-Policy': 'Cross-Origin-Embedder-Policy: require-corp',
        'Cross-Origin-Resource-Policy': 'Cross-Origin-Resource-Policy: same-site',
        'Set-Cookie': None
    }

    score = 0
    total_headers = len(recommended_headers)
    satisfied = {}
    not_satisfied = {}
    missing = {}
    raw_headers = {}
    http_info = {}
    https_info = {}

    # Define HTTP information headers to include
    http_information_headers = [
        'Content-Type', 'Content-Length', 'Date', 'Server', 'ETag', 'Last-Modified',
        'Cache-Control', 'X-Cache', 'Via', 'X-Amz-Cf-Pop', 'Alt-Svc', 'X-Amz-Cf-Id', 'Age'
    ]

    # Define HTTPS information headers to include
    https_information_headers = ['Connection', 'Accept-Ranges']

    try:
        time.sleep(2)  # Simulate scanning delay
        response = requests.get(url)
        headers = response.headers

        # Capture HTTP information such as status, content-type, etc.
        http_info = {
            'status_code': response.status_code,
            'content_type': headers.get('Content-Type', 'N/A'),
            'content_length': headers.get('Content-Length', 'N/A'),
            'date': convert_to_pht(headers.get('Date', 'N/A')),
            'server': headers.get('Server', 'N/A'),
            'etag': headers.get('ETag', 'N/A'),
            'last_modified': convert_to_pht(headers.get('Last-Modified', 'N/A')),
            'cache_control': headers.get('Cache-Control', 'N/A'),
            'x_cache': headers.get('X-Cache', 'N/A'),
            'via': headers.get('Via', 'N/A'),
            'x_amz_cf_pop': headers.get('X-Amz-Cf-Pop', 'N/A'),
            'alt_svc': headers.get('Alt-Svc', 'N/A'),
            'x_amz_cf_id': headers.get('X-Amz-Cf-Id', 'N/A'),
            'age': headers.get('Age', 'N/A'),
            'site_name': url,
            'ip_address': socket.gethostbyname(socket.gethostbyname(url.split('/')[2])) 
        }

        # Separate HTTPS information headers
        https_info = {k: headers.get(k) for k in https_information_headers if k in headers}

        # Filter raw headers to exclude HTTP and HTTPS information
        raw_headers = {k: v for k, v in headers.items() if k not in http_information_headers and k not in https_information_headers}

        # Evaluate headers
        for header, recommended_value in recommended_headers.items():
            if header in headers:
                actual_value = headers[header]
                if recommended_value is None or actual_value == recommended_value:
                    satisfied[header] = actual_value
                    score += 1
                else:
                    not_satisfied[header] = {
                        'value': actual_value,
                        'recommendation': recommendations.get(header, "No recommendation available.")
                    }
            else:
                missing[header] = {
                    'description': missing_descriptions.get(header, "No description available."),
                    'recommendation': recommendations.get(header, "No recommendation available.")
                }

        # Determine grade
        # Include Percentage
        grade = determine_grade(score, total_headers)

        # Return all info
        return {
            'satisfied': satisfied,
            'not_satisfied': not_satisfied,
            'missing': missing,
            'raw_headers': raw_headers,
            'http_info': http_info,
            'https_info': https_info,
            'grade': grade,
            'score': score,
            'total_headers': total_headers
        }

    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def determine_grade(score, total):
    percentage = (score / total) * 100
    if percentage == 100:
        return "S"
    elif percentage >= 90:
        return "A"
    elif percentage >= 80:
        return "B"
    elif percentage >= 70:
        return "C"
    elif percentage >= 60:
        return "D"
    elif percentage >= 50:
        return "E"
    else:
        return "F"

def take_screenshot(url):
    # Configure Selenium options
    chrome_options = ChromeOptions()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")  # Optional for certain environments
    print("Chrome Options:", chrome_options.arguments)


    # Create a webdriver instance
    driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
    
    # Open the URL
    driver.get(url)

    # Wait for a specific element to load (e.g., the body element)
    try:
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
    except Exception as e:
        print(f"Error waiting for page to load: {e}")

    # Take a screenshot
    screenshot_path = "screenshot.png"
    driver.save_screenshot(screenshot_path)

    # Close the browser
    driver.quit()

    # Return the path to the screenshot
    return screenshot_path



@app.route('/', methods=['GET', 'POST'])
def home():
    report = None
    url = None
    screenshot_path = None

    if request.method == 'POST':
        url = request.form['url']
        report = evaluate_security_headers(url)

        # Take a screenshot if evaluation is successful
        if not report.get('error'):
            screenshot_path = take_screenshot(url)

    return render_template('index.html', report=report, url=url, screenshot_path=screenshot_path)

@app.route('/screenshot')
def screenshot():
    # Send the screenshot image
    return send_file("../screenshot.png", mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True)