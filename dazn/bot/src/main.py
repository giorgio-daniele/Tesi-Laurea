import math
import os
import shutil
import subprocess
import sys
import time

import pyautogui
import pydirectinput

X_OFFSET = 500
Y_OFFSET = 250

X_REL_DESKTOP = 500
X_REL_MOBILE  = 150
Y_REL_DESKTOP = 70
Y_REL_MOBILE  = 70
SCROLL_DESKTOP = 115
SCROLL_MOBILE  = 280

DAZN = {
    "home": {
        "name":  "home",
        "image": "canalitv.png",
        "desktop": {
            "xrel": None,
            "yrel": None,
            "url": "https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff"
        },
        "mobile": {
            "xrel": 0,
            "yrel": 0,
        }
    },
    "channels": [{
        "name":  "eurosport1",
        "image": "eurosport1.png",
        "desktop": {
            "xrel": None,
            "yrel": None,
            "url":  "https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff/2q7dj9g3q9k5o9dkncw7u8l36"
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   0,
            "scroll": 0,
        }
    }, {
        "name":  "zonadazn",
        "image": "zonadazn.png",
        "desktop": {
            "xrel": None,
            "yrel": None,
            "url":  "https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff/2sag7dm3qetjoyiuxpr9xqobw"
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE,
            "scroll": 0
        }
    }, {
        "name":  "nfltv",
        "image": "nfltv.png",
        "desktop": {
            "xrel": None,
            "yrel": None,
            "url":  "https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff/81ndwrnyor5g51kraulei80t0",
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 2,
            "scroll": 0
        }
    }, {
        "name":  "milantv",
        "image": "milantv.png",
        "desktop": {
            "xrel": None,
            "yrel": None,
            "url": f"https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff/8t2b2ul1hx7y00wn0hvggbgzi",
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 3,
            "scroll": 0
        }
    }, {
        "name":  "intertv",
        "image": "intertv.png",
        "desktop": {
            "xrel": None,
            "yrel": None,
            "url":  "https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff/a7w58213g6pgi4owynyikw0pg",
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 4,
            "scroll": 0
        }
    }, {
        "name":  "eurosport2",
        "image": "eurosport2.png",
        "desktop": {
            "xrel": None,
            "yrel": None,
            "url": f"https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff/eddggydwal0i1620hbjrk3ahw",
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 5,
            "scroll": 0
        }
    }]
}

SNIFFER = {
    "name":  "tshark",
    "path":  r"C:\\Program Files\\Wireshark\\tshark.exe",
    "len":   "2500",
    "iface": "Wi-Fi",
}

SHORT_TIME = 10 # in seconds
LONG_TIME  = 60 # in seconds

HUMAN_FACTOR = 2
TIME_SHEET = {
    "idling":   LONG_TIME  * 10,
    "startup":  SHORT_TIME * 2,
    "loading":  SHORT_TIME,
    "watching": SHORT_TIME * 6,
    "cooling":  SHORT_TIME * 2,
    "human":    HUMAN_FACTOR,
}

REPETIONS = {
    "times": 20
}

# Timing functions
def delay(millis):
    millis = millis * 1000
    target = time.perf_counter() + (millis / 1000)
    while time.perf_counter() < target:
        pass

def current_millis():
    return time.time() * 1000

# Logging functions
def log_event(name, origin, log):
    now = current_millis()
    time_difference = now - origin
    log.write(f"{name}\t{now}\t{time_difference}\t{time_difference / 1000}\n")

def log_origin(log):
    origin = current_millis()
    log.write("EVENT\tUNIX_TS\tFROM_ORIGIN_MS\tFROM_ORIGIN_S\n")
    log_event("origin", origin, log)
    return origin

# Sniffer functions
def start_sniffer(pcap_file):
    cmd = [
        SNIFFER["path"],
        "-i", SNIFFER["iface"],
        "-w", pcap_file,
        "-s", SNIFFER["len"]
    ]
    return subprocess.Popen(
        cmd,
        creationflags=subprocess.CREATE_NO_WINDOW,
        shell=False,
        stdin=None,
        stderr=None)

def stop_sniffer(sniffer):
    if sniffer:
        sniffer.terminate()
        sniffer.wait()

# Actions
def right_click():
    pyautogui.rightClick()

def single_click():
    pyautogui.click()

def double_click():
    pyautogui.doubleClick()

def scroll_down(clicks, speed=0.00001, width_ratio=0.2):
    screen_width, screen_height = pyautogui.size()
    vertical_center = screen_height // 2
    cursor_x = int(screen_width * width_ratio)
    pyautogui.moveTo(cursor_x, vertical_center)

    for _ in range(clicks):
        pyautogui.scroll(-10)
        time.sleep(speed)

def click_icon(pic, twice):
    err = f"Error: {pic} not found"
    try:
        pos = pyautogui.locateOnScreen(
            pic,
            grayscale=True,
            confidence=0.9)
        if pos:
            pyautogui.moveTo(
                pyautogui.center(pos))
            if twice is True:
                double_click()
            else:
                single_click()
        else:
            raise FileNotFoundError(err)
    except pyautogui.ImageNotFoundException:
        raise FileNotFoundError(err)

def move_to_icon(pic):
    err = f"Error: {pic} not found"
    try:
        pos = pyautogui.locateOnScreen(
            pic,
            grayscale=True,
            confidence=0.9)
        if pos:
            pyautogui.moveTo(
                pyautogui.center(pos))
        else:
            raise FileNotFoundError(err)
    except pyautogui.ImageNotFoundException:
        raise FileNotFoundError(err)

def icon_exists(pic):
    try:
        pos = pyautogui.locateOnScreen(
            pic,
            grayscale=True,
            confidence=0.9)
        return True if pos else False
    except pyautogui.ImageNotFoundException:
        return False

def go_left(distance, angle=0):
    x = distance * math.cos(angle)
    y = distance * math.sin(angle)
    pyautogui.moveRel(x, y)

def go_down(distance):
    angle = math.pi / 2
    x = distance * math.cos(angle)
    y = distance * math.sin(angle)
    pyautogui.moveRel(x, y)


def alt_f4():
    pyautogui.hotkey("alt", "f4")


def alt_s():
    pydirectinput.keyDown("alt")
    pydirectinput.press("s")
    pydirectinput.keyUp("alt")


def alt_b():
    pydirectinput.keyDown("alt")
    pydirectinput.press("b")
    pydirectinput.keyUp("alt")


def navigate_browser(url):
    pyautogui.hotkey("ctrl", "l")
    pyautogui.write(url)
    pyautogui.press("enter")


def navigate_app(reference, xrel, yrel):
    try:
        move_to_icon(reference)
        go_left(xrel)
        go_down(yrel)
        single_click()
    except pyautogui.ImageNotFoundException as err:
        raise FileNotFoundError(err)


# DAZN functions
def start_dazn(platform, images):
    try:
        if platform == "desktop":
            click_icon(pic=os.path.join(images, "dazn.png"),
                       twice=True)
        if platform == "mobile":
            click_icon(pic=os.path.join(images, "dazn.png"),
                       twice=False)
    except Exception as error:
        raise FileNotFoundError(error)


def stop_dazn(platform, images):
    try:
        if platform == "desktop":
            alt_f4()
        if platform == "mobile":
            alt_s()
            delay(TIME_SHEET["human"])
            click_icon(os.path.join(images, "exit.png"), False)
    except Exception as error:
        raise FileNotFoundError(error)

# def watch_in_browser(sequence, events, origin):
#     for i, point in enumerate(sequence):
#         if i % 2 == 0:
#             navigate_browser(point["url"])
#             delay(TIME_SHEET["loading"])
#         else:
#             navigate_browser(point["url"])
#             log_event(f"{point["name"]}-on", origin, events)
#             delay(TIME_SHEET["watching"])
#             log_event(f"{point["name"]}-off", origin, events)


# def watch_in_app(sequence, images, events, origin):
#     try:
#         for i, point in enumerate(sequence):
#             if i % 2 == 0:

#                 # Notice: sometimes a live streaming
#                 # may be live for real. I observerd
#                 # that built-in toolbar disppears, so
#                 # to prevent such scenario, just
#                 # rely on Android back button

#                 if icon_exists(os.path.join(
#                         images,
#                         DAZN["toolbar"]["image"]["name"])):
#                     click_icon(os.path.join(
#                         images,
#                         point["image"]["name"]),
#                         False)

#                 # If the toolbar exists, just follow
#                 # the sequence as usual    
#                 else:
#                     click_icon(os.path.join(
#                         images,
#                         DAZN["back"]["image"]["name"]),
#                         False)
#                 delay(TIME_SHEET["loading"])
#             else:
#                 navigate_app(
#                     os.path.join(
#                         images,
#                         sequence[1]["image"]["name"]),
#                     point["image"]["xrel"],
#                     point["image"]["yrel"])
#                 log_event(f"{point["name"]}-on", origin, events)
#                 delay(TIME_SHEET["watching"])
#                 log_event(f"{point["name"]}-off", origin, events)
#     except Exception as error:
#         raise FileNotFoundError(error)


def navigate_app(reference, xrel, yrel):
    try:
        move_to_icon(reference)
        go_left(xrel)
        go_down(yrel)
        single_click()
    except pyautogui.ImageNotFoundException as err:
        raise FileNotFoundError(err)

def watch_n(channels, platform, images, events, origin):
    try:

        if platform == "mobile":
            click_icon(os.path.join(images, DAZN["home"][platform]["image"]), False)
        if platform == "desktop":
            navigate_browser(DAZN["home"][platform]["url"])
        delay(TIME_SHEET["loading"])

        for channel in channels:
            if platform == "mobile":
                # Scroll down if necessary
                scroll = channel[platform]["scroll"]
                if scroll > 0:
                    width = 0.5
                    if platform == "mobile":
                        width = 0.2
                    scroll_down(
                        clicks=scroll,
                        speed=0.00001,
                        width_ratio=width)

                # Set the reference
                reference = os.path.join(images, channels[0]["image"])
                xrel = channel[platform]["xrel"]
                yrel = channel[platform]["yrel"]

                # Start watching the live content
                navigate_app(reference, xrel, yrel)
            if platform == "desktop":
                navigate_browser(channel[platform]["url"])

            log_event(f"{channel["name"]}-on", origin, events)

            # Watch the event for a while
            delay(TIME_SHEET["watching"])

            # Close the stream
            if platform == "desktop":
                navigate_browser(DAZN["home"][platform]["url"])
                log_event(f"{channel["name"]}-off", origin, events)
            if platform == "mobile":
                right_click()
                log_event(f"{channel["name"]}-off", origin, events)
            # Await before next channels
            delay(TIME_SHEET["loading"])
    except Exception as error:
        raise FileNotFoundError(error)

def run_experiment(platform, number, i, result):
    err = False
    log = os.path.join(result, f"events-{i}.csv")
    cap = os.path.join(result, f"traces-{i}.pcap")

    if os.path.exists(log):
        os.remove(log)
    if os.path.exists(cap):
        os.remove(cap)

    sniffer = None
    events  = None

    try:
        events = open(log, "a+")
        origin = log_origin(events)
        sniffer = start_sniffer(cap)
        log_event("sniffer-on", origin, events)

        if number == 0:
            delay(TIME_SHEET["idling"])

        if number == 1:
            start_dazn(platform, images)
            log_event("sky-on", origin, events)
            delay(TIME_SHEET["startup"])
            channels = DAZN["channels"][:1]
            watch_n(channels, platform, images, events, origin)
            stop_dazn(platform, images)
            log_event("sky-off", origin, events)

        if number == 2:
            start_dazn(platform, images)
            log_event("sky-on", origin, events)
            delay(TIME_SHEET["startup"])
            channels = DAZN["channels"][:len(DAZN["channels"])]
            watch_n(channels, platform, images, events, origin)
            stop_dazn(platform, images)
            log_event("sky-off", origin, events)

    except Exception as error:
        print("---------------------")
        print("An exception occurred")
        print(f"Running {i + 1} iteration of {number} on {platform} caused:")
        print(error)
        err = True

    finally:
        if sniffer:
            delay(TIME_SHEET["cooling"])
            stop_sniffer(sniffer)
            log_event("sniffer-off", origin, events)
        if events:
            events.close()
        if err:
            if os.path.exists(log):
                os.remove(log)
            if os.path.exists(cap):
                os.remove(cap)


# Main function
if __name__ == "__main__":

    usage = f"""Usage:
    python nain.py [platform] [number] [folder]

    [platform] should be one of the following:
        - desktop (windows)
        - mobile (android)
    [experiment] should be one of the following:
        - 0 (noise capture)
        - 1 (single channel)
        - 2 (multiple channels)
    For instance:
        python main.py desktop test0
    """

    if len(sys.argv) < 4:
        print(usage)
        exit(1)

    program  = sys.argv[0]
    platform = sys.argv[1]
    number   = int(sys.argv[2])
    folder   = sys.argv[3]

    print("-------------------------------")
    print(f"Program:\t{program}")
    print(f"Testbed:\t{platform}")
    print(f"Number:\t{number}")
    print(f"Folder:\t{folder}")
    print("-------------------------------")

    if platform in ["desktop", "mobile"]:

        cwd = os.getcwd()
        images = os.path.join(cwd, "images",  platform)
        result = os.path.join(cwd, "results", folder)

        if os.path.exists(result):
            shutil.rmtree(result)
        os.makedirs(result)

        for i in range(0, REPETIONS["times"]):
            run_experiment(platform, number, i, result)

    else:
        print("Unknown platform")
        exit(1)
    print("Done")
