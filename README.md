# Proxy Rotator :rocket:

A lightweight and efficient tool designed to manage and rotate through proxy configurations. It automatically fetches subscription URLs, decodes them (handling both raw text and Base64 encoded formats), and tests the proxies to save only the working ones for fast and reliable internet connectivity.

## Features :memo:

-   **Automatic Subscription Fetching:** Fetches proxy lists from subscription URLs.
-   **Base64 Decoding:** Automatically detects and decodes Base64 encoded subscription content.
-   **Proxy Rotation:** Connects to the internet using a random proxy from the working pool for each request.
-   **Health Checking:** Tests and validates proxies, saving only the working configurations to a dedicated list.
-   **Persistence:** Maintains a persistent list of working proxies to ensure fast connection times on subsequent runs.

## How It Works :sparkles:

1.  **Fetch:** The application retrieves the proxy list from the provided subscription URL.
2.  **Decode:** If the content is Base64 encoded, it decodes it into plain text.
3.  **Parse:** Extracts individual proxy configurations (e.g., SOCKS, HTTP) from the text.
4.  **Test & Save:** Each proxy is tested for connectivity and speed. Only the functional proxies are saved to a database file.
5.  **Rotate:** When making outbound requests, the application randomly selects a proxy from the validated pool of working configurations.

## Installation :book:

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

### Basic Setup :truck:

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

### Configuration Variables :wrench:

**For most users, it's recommended to leave these variables at their default values. Only modify them if you have specific performance or operational requirements.**

| Variable | Description |
| :--- | :--- |
| `subscription_url` | The URL of your subscription source. This can be a raw text file or a base64-encoded string. |
| `listening_socks_port` | The local port used for incoming SOCKS connections. |
| `subscription_update_time` | The interval, in seconds, for checking the `subscription_url` for new content. |
| `max_samples_batch` | The maximum number of random configurations to select from the subscription URL for testing in a single batch. |
| `min_working_configs` | The minimum number of working configurations required. If the number of found working configurations falls below this value, a new batch of configs will be tested immediately. |
| `url_test_timeout` | The maximum time, in seconds, to wait for a connection to a configuration to determine if it's working. |
| `config_update_time` | The delay, in seconds, between each individual configuration test. |


### Understanding and Modifying Variables 

The following variables are central to the project's operation. While we've set them to sensible defaults, advanced users may want to fine-tune them. **If you're not an expert, it's highly recommended you leave them as they are.** Incorrect values can lead to instability or unexpected behavior.

---

### Core Configuration

* `subscription_url`
    This is the **source of your configurations**. The program fetches its list of potential connections from this URL. The URL can point to a simple text file with each configuration on a new line, or it can contain a **Base64-encoded string**. The program will automatically detect and decode the content if it's Base64.
    
* `listening_socks_port`
    This variable defines the **local port** on which the application will listen for incoming SOCKS proxy connections. When another application on your system wants to use the proxy, it will connect to `127.0.0.1` (localhost) at this specific port. You can change this if the port is already in use by another program.
    
* `subscription_update_time`
    This value, in **seconds**, controls how often the program checks the `subscription_url` for updates. A lower value means the program will check for new configurations more frequently, which can be useful if your subscription list changes often. A higher value reduces network traffic and server load.

---

### Performance Tuning :zap:

* `max_samples_batch`
    To avoid testing every single configuration from a large subscription list, the program tests them in batches. This variable determines the **maximum number of random configurations** to select and test from the subscription list at one time. A larger batch size can find working configurations faster, but it also uses more resources and may be blocked by firewalls.
    
* `min_working_configs`
    This is a critical variable for ensuring a stable connection. It sets the **minimum number of active, working configurations** the program tries to maintain. If the number of working configs drops below this threshold, the program will immediately initiate a new test batch (of size `max_samples_batch`) to find replacements.
    
* `url_test_timeout`
    When the program tests a configuration, it needs to know how long to wait before giving up. This value, in **seconds**, is the **maximum time allowed for a single test connection** to succeed. A lower timeout can speed up the testing process, but it may incorrectly fail configurations from servers that are just a little slow to respond.
    
* `config_update_time`
    This variable, in **seconds**, introduces a **delay between each individual configuration test**. This is a useful setting to prevent overwhelming a server or to avoid being flagged as a bot. It staggers the test requests, making them appear more like organic traffic.


## Acknowledgments 🎁

A special thank you to the projects and resources that were instrumental in the development of this project:

*   [v2ray2json]([https://github.com/user/repo](https://github.com/arminmokri/v2ray2json)) - I used directly, the `v2ray2json.py` from this repo.
*   [Xray-Fragment-Finder]([https://github.com/user/repo2](https://github.com/sasanxxx/Xray-Fragment-Finder)) - I used directly, the `setup.bat` from this repo.

