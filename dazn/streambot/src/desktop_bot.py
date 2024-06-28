import random
import os
import time
import math
import subprocess
import pyautogui
import pydirectinput
import argparse

X_OFFSET = 150
Y_OFFSET = 70
S_OFFSET = 250

PARAMETERS = {

    # Define the homepage, from which each stream starts
    "home": {
        "image": "canalitv.png",
        "url":   "https://www.dazn.com/it-IT/sport/Sport:9kn3pow0we2r8hna2p0k4m2ff"
    }, 

    # Define the list of all domestic italian channels
    "italy": [
        { "name": "eurosport1", "url": "https://www.dazn.com/it-IT/fixture/ContentId:2q7dj9g3q9k5o9dkncw7u8l36/2q7dj9g3q9k5o9dkncw7u8l36/1b7lkqmn498j81e73n1yrmqx2c" },
        { "name": "zonadazn",   "url": "https://www.dazn.com/it-IT/fixture/ContentId:2sag7dm3qetjoyiuxpr9xqobw/2sag7dm3qetjoyiuxpr9xqobw/18qcdgg4xnsj11csitm45xw5hi" },
        { "name": "nfltv",      "url": "https://www.dazn.com/it-IT/fixture/ContentId:81ndwrnyor5g51kraulei80t0/81ndwrnyor5g51kraulei80t0/rveqynjyjzy11h2iinqe1jje0" },
        { "name": "milantv",    "url": "https://www.dazn.com/it-IT/fixture/ContentId:8t2b2ul1hx7y00wn0hvggbgzi/8t2b2ul1hx7y00wn0hvggbgzi/1pkkdf79afgt41b1yg7d3pisvp" },
        { "name": "intertv",    "url": "https://www.dazn.com/it-IT/fixture/ContentId:a7w58213g6pgi4owynyikw0pg/a7w58213g6pgi4owynyikw0pg/zo0hyyfu9b1z1cgtygdjvbkcy" },
        { "name": "eurosport2", "url": "https://www.dazn.com/it-IT/fixture/ContentId:eddggydwal0i1620hbjrk3ahw/eddggydwal0i1620hbjrk3ahw/s5jssu34hgh31vemb9znxfq2z" },
    ],
}

# Timing options (edit here depending on your necessities)
TIME_BASE = 10

def await_millis(ms: int):

    ms = ms * 1000
    mx = time.perf_counter() + (ms / 1000)
    while time.perf_counter() < mx:
        pass


def current_millis():
    return time.time() * 1000


def log_event(name, origin, file):

    now = current_millis()
    time_difference = now - origin
    file.write(f"{name}\t{now}\t{time_difference}\t{time_difference / 1000}\n")


def log_origin(file):

    origin = current_millis()
    file.write("EVENT\tUNIX_TS\tFROM_ORIGIN_MS\tFROM_ORIGIN_S\n")
    log_event("origin", origin, file)

    return origin


class Wireshark():

    def __init__(self, exe_path: str, net_iface: str, out_file:str, pkt_limit=2500):

        self.exe_path = os.path.abspath(exe_path)
        self.out_file = os.path.abspath(out_file)
        self.pkt_limit = pkt_limit
        self.net_iface = net_iface
        self.process = None


    def start(self):

        args = [self.exe_path, "-i", self.net_iface, "-w", self.out_file, "-s", self.pkt_limit]

        # Try to launch a Wireshark instance in the system
        try:
            self.process = subprocess.Popen(
                args, creationflags=subprocess.CREATE_NO_WINDOW, shell=True)
            return True
        except (OSError, ValueError) as e:
            return False
        except Exception as e:
            return False


    def stop(self):

        # Try to terminate the process tree
        if self.process:
            try:
                # Use taskkill to terminate the process tree
                taskkill_cmd = f"taskkill /F /IM \"tshark.exe\""
                subprocess.run(taskkill_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            except subprocess.CalledProcessError as e:
                pass
            finally:
                self.process = None


class DaznDesktopApp():

    def __init__(self, img_path):
        
        # The path where images are stored
        self.img_path = img_path

    def start(self):

        icon_name = "dazn.png"
        icon_path = os.path.join(self.img_path, icon_name)

        try:
            pos = pyautogui.locateOnScreen(icon_path, grayscale=True, confidence=0.9)
            if pos:
                pyautogui.moveTo(pyautogui.center(pos))
                pyautogui.doubleClick()
                return True
            return False
        except pyautogui.ImageNotFoundException:
            print(f"{icon_name} not found")
            return False

    def stop(self):

        try:
            # Use taskkill to terminate the process tree (the Browser)
            taskkill_cmd = f"taskkill /F /IM \"chrome.exe\""
            subprocess.run(taskkill_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True

        except subprocess.CalledProcessError as e:
            return False


    def jump_to_home(self):

        url = PARAMETERS["home"]["url"]

        pyautogui.hotkey("ctrl", "l")
        pyautogui.write(url)
        pyautogui.press("enter")

        return True


    def return_to_home(self):

        url = PARAMETERS["home"]["url"]

        pyautogui.hotkey("ctrl", "l")
        pyautogui.write(url)
        pyautogui.press("enter")

        return True


    def go_channel(self, channel):

        url = channel["url"]

        pyautogui.hotkey("ctrl", "l")
        pyautogui.write(url)
        pyautogui.press("enter")

        return True


class Sample():

    def __init__(self, number: int, shark: Wireshark, dazn: DaznDesktopApp, trace: str):

        # DAZN and Wireshark
        self.dazn  = dazn
        self.shark = shark

        # Experiment settings
        self.number = number

        # Trace file
        self.trace = trace

    def start_experiment(self):
        channels = []
        
        # Open the file for writing the Streambot trace
        f = open(self.trace, "w")
        
        # Log the origin of the experiment
        origin = log_origin(f)

        # Define a helper function to handle errors
        def handle_error(message):
            print(message)
            self.dazn.stop()
            self.shark.stop()
            f.close()
            await_millis(TIME_BASE)
            return False

        # Start the sniffer (step 1)
        if not self.shark.start():
            return handle_error("Error on starting Wireshark")
        
        log_event("sniffer-on", origin, f)

        # Start Sky (step 2)
        if not self.dazn.start():
            return handle_error("Error on starting DAZN application")
        
        log_event("dazn-on", origin, f)
        
        # Await before starting the experiment
        await_millis(TIME_BASE * 2)

        # Determine channels based on the experiment number
        channel_mapping = {
            1: PARAMETERS["italy"][:1],  # Test just a channel
            2: PARAMETERS["italy"][:],   # Test international channels
        }

        channels = channel_mapping.get(self.number, [])

        # Start watching channels (step 3)
        if not self.dazn.jump_to_home():
            return handle_error("Error on getting channels list")
        
        # Await before watching the first channel
        await_millis(TIME_BASE)

        # Watch all channels
        for channel in channels:
            if not self.dazn.go_channel(channel):
                return handle_error("Error on getting a channel")
            
            # Log the channel has been opened
            log_event(f"{channel['name']}-on", origin, f)
            
            # Watch the stream for a random duration between 40 and 60 seconds
            await_millis(random.randint(40, 60))
            
            # Log the channel has been closed
            log_event(f"{channel['name']}-off", origin, f)
            
            # Go back to home
            if not self.dazn.return_to_home():
                return handle_error("Error on going back")
            
            # Await before the next channel for a random duration between 5 and 15 seconds
            await_millis(random.randint(5, 15))

        # Stop Sky
        self.dazn.stop()
        log_event("dazn-off", origin, f)

        # Stop the sniffer
        self.shark.stop()
        log_event("sniffer-off", origin, f)

        # Close the file
        f.close()

        # Await before stepping into the next experiment
        await_millis(TIME_BASE)

        # Get the screen size
        w, h = pyautogui.size()

        # Generate the coordinates of the center
        x = int(w * 0.5)
        y = h // 2

        # Move the mouse to the center of the screen
        # (avoiding to hide the icon for next round)
        pyautogui.moveTo(x, y)

        return True


def main(number, repetitions, interface, results_folder_name):

    # The path where results will be stored
    main_dir = os.path.join(os.getcwd(), "results", results_folder_name)

    if not os.path.exists(main_dir):
        os.makedirs(main_dir)

    # Edit here the path of Wireshark and SkyGo
    shark_exe_path = r"C:\\Program Files\\Wireshark\\tshark.exe"

    for i in range(repetitions):

        platform = "desktop"

        print(f"{'_' * 100}")
        print(f"Running experiment {number}")
        print(f"\tIteration n° = {i + 1}")

        # Define the ouput file for Wireshark
        wireshark_file_path = os.path.join(main_dir, f"wireshark_trace-{i}.pcap")

        # Define the output file for Streambot
        streambot_file_path = os.path.join(main_dir, f"streambot_trace-{i}.csv")

        # Generate a new instance of Wireshark application conteoller
        sniffer = Wireshark(exe_path=shark_exe_path, net_iface=interface, out_file=wireshark_file_path, pkt_limit="2500")
        
        # Generate a new instance of SkyGo application controller
        service = DaznDesktopApp(img_path=os.path.join(os.getcwd(), "images", platform))

        # Generate a new instance of Experiment controller
        sample = Sample(number=number, shark=sniffer, dazn=service, trace=streambot_file_path)

        if sample.start_experiment():
            print("\t---> Experiment has success")

        else:
            print("\t---> Experiment has failed")

            # Remove file
            os.remove(wireshark_file_path)
            os.remove(streambot_file_path)

        print(f"{'_' * 100}")


if __name__ == "__main__":

    # Generate an object with all the configurations
    parser = argparse.ArgumentParser(description='Run experiments with specified parameters.')

    # Add the argument to the command line
    parser.add_argument('--number', type=int, default=1, choices=[1, 2], help='Experiment number')
    parser.add_argument('--repetitions', type=int, default=10, help='Number of repetitions')
    parser.add_argument('--interface', type=str, default='Wi-Fi', help='Interface')

    args = parser.parse_args()

    # Run the main program
    main(number=args.number, repetitions=args.repetitions, interface=args.interface, results_folder_name="test-0")
