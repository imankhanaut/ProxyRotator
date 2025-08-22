# Proxy Rotator

A lightweight and efficient tool designed to manage and rotate through proxy configurations. It automatically fetches subscription URLs, decodes them (handling both raw text and Base64 encoded formats), and tests the proxies to save only the working ones for fast and reliable internet connectivity.

## Features

-   **Automatic Subscription Fetching:** Fetches proxy lists from subscription URLs.
-   **Base64 Decoding:** Automatically detects and decodes Base64 encoded subscription content.
-   **Proxy Rotation:** Connects to the internet using a random proxy from the working pool for each request.
-   **Health Checking:** Tests and validates proxies, saving only the working configurations to a dedicated list.
-   **Persistence:** Maintains a persistent list of working proxies to ensure fast connection times on subsequent runs.

## How It Works

1.  **Fetch:** The application retrieves the proxy list from the provided subscription URL.
2.  **Decode:** If the content is Base64 encoded, it decodes it into plain text.
3.  **Parse:** Extracts individual proxy configurations (e.g., SOCKS, HTTP) from the text.
4.  **Test & Save:** Each proxy is tested for connectivity and speed. Only the functional proxies are saved to a database file.
5.  **Rotate:** When making outbound requests, the application randomly selects a proxy from the validated pool of working configurations.

## Installation

1.  Clone this repository:
    ```bash
    git clone https://github.com/imankhanaut/ProxyRotator.git
    cd proxy-rotator
    ```
2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Copy the xray executable inside dir. If you are inside linux you should make *xray* executable:
    ```bash
    chmod +x xray
    ```

    Moreover, if you are inside windows, run **setup.bat** to copy xray inside the local folder.


## Usage

### Basic Setup

1.  Inside the ProxyRotator.py file, you can change the subscription url with subscription_url and listening port with listening_socks_port.
The default for subscription url is the Mahsa Freenet configs. and default listening port is 7590.

2. You can run the application with

   ```bash
   python3 ProxyRotator.py
   ```

### Command-Line Arguments

You can also configure the tool via command-line arguments:

1. Using a custom URL provided at runtime

    ```bash
    python3 ProxyRotator.py <URL>
    ```

3. Specify a custom inbound port
   
    ```bash
    python3 ProxyRotator.py <URL> <inbound port>
    ```

5. Specify not to use the saved configs

    ```bash
    python3 ProxyRotator.py <URL> <inbound port> no_use
    ```
