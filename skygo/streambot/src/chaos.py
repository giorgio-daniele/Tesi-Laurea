import requests
import threading
import time
import random  # Importa il modulo random

def send_request(url):
    """
    Function that sends an HTTP GET request to the specified URL.
    :param url: The URL to send the request to.
    """
    try:
        response = requests.get(url)
        print(f"Request sent to {url}, status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

def generate_traffic(urls, duration):
    """
    Function that generates network traffic by sending HTTP GET requests to the specified URLs for 
    a defined duration with random intervals between requests.
    :param urls: List of URLs to send the requests to.
    :param duration: Total duration to generate traffic (in seconds).
    """
    end_time = time.time() + duration
    threads = []
    
    try:
        while time.time() < end_time:
            for url in urls:
                # Generate random interval between 1 to 10 seconds
                interval = random.uniform(1, 3)
                time.sleep(interval)  # Wait for the random interval
                
                thread = threading.Thread(target=send_request, args=(url,))
                thread.start()
                threads.append(thread)
    except KeyboardInterrupt:
        print("\nTraffic generation interrupted. Exiting gracefully.")
    
    # Ensure all threads have completed
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # List of websites to target
    urls = [
        "https://www.youtube.com",
        "https://www.google.com",
        "https://www.facebook.com",
        "https://www.amazon.com",
        "https://www.wikipedia.org",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.instagram.com",
        "https://www.reddit.com",
        "https://www.ebay.com",
        "https://www.netflix.com",
        "https://www.twitch.tv",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.github.com",
        "https://www.stackoverflow.com"
    ]

    duration = 60 * 60  # Duration in seconds (60 minutes)

    generate_traffic(urls, duration)
