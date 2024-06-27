import random
import os
import time
import math
import subprocess
import pyautogui
import pydirectinput
import argparse

X_OFFSET = 500
Y_OFFSET = 60
S_OFFSET = 115

PARAMETERS = {

    # Define the homepage, from which each stream starts
    "home": {
        "image": "canalitv.png",
        "x-val": 0, # x-axis relative value
        "y-val": 0, # y-axis relative value
        "s-val": 0, # scroll relative value
    }, 

    # Define the list of all domestic italian channels
    "italy": [
        # Canali RAI
        { "name": "skytg24", "image": "skytg24.png", "x-val": 0, "y-val": 0, "s-val": 0 },
        { "name": "raiuno",  "image": "raiuno.png",  "x-val": 0, "y-val": Y_OFFSET, "s-val": 0 },
        { "name": "raidue",  "image": "raidue.png",  "x-val": 0, "y-val": Y_OFFSET * 2, "s-val": 0 },
        { "name": "raitre",  "image": "raitre.png",  "x-val": 0, "y-val": Y_OFFSET * 3, "s-val": 0 },
        # Canali Mediaset
        { "name": "retequattro",    "image": "retequattro.png",  "x-val": 0, "y-val": Y_OFFSET * 4, "s-val": 0 },
        { "name": "canalecinque",   "image": "canalecinque.png", "x-val": 0, "y-val": Y_OFFSET * 5, "s-val": 0 },
        { "name": "italiauno",      "image": "italiauno.png",    "x-val": 0, "y-val": Y_OFFSET * 6, "s-val": 0 },
    ],

    # Define the list of all international channels 
    "globe": [
        { "name": "skysportuno",    "image": "skysportuno.png",     "x-val": 0, "y-val": 0, "s-val": S_OFFSET },
        { "name": "skysportcalcio", "image": "skysportcalcio.png",  "x-val": 0, "y-val": Y_OFFSET, "s-val": int(S_OFFSET / 10) },
        { "name": "skysporttennis", "image": "skysporttennis.png",  "x-val": 0, "y-val": Y_OFFSET * 2, "s-val": int(S_OFFSET / 10) },
        { "name": "skysportmax",    "image": "skysportmax.png",     "x-val": 0, "y-val": Y_OFFSET * 3, "s-val": int(S_OFFSET / 10) },
        { "name": "skysportgolf",   "image": "skysportgolf.png",    "x-val": 0, "y-val": Y_OFFSET * 4, "s-val": int(S_OFFSET / 10) },
        { "name": "skysportf1",     "image": "skysportf1.png",      "x-val": 0, "y-val": Y_OFFSET * 5, "s-val": int(S_OFFSET / 10) },
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


class SkyGoDesktopApp():

    def __init__(self, exe_path, img_path):
        
        # The path of the executable file
        self.exe_path = exe_path

        # The path where images are stored
        self.img_path = img_path

        # The instance of SkyGoDesktop application itself
        self.process = None

    def start(self):

        # Generate argument for launching the application
        args = [self.exe_path]

        try:
            # Launch a new instance of SkyGo Desktop App
            self.process = subprocess.Popen(args, creationflags=subprocess.CREATE_NO_WINDOW, shell=True)
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
                taskkill_cmd = f"taskkill /F /IM \"Sky Go.exe\""
                subprocess.run(taskkill_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            except subprocess.CalledProcessError as e:
                pass
            finally:
                self.process = None


    def jump_to_home(self):

        icon_name = PARAMETERS["home"]["image"]
        icon_path = os.path.join(self.img_path, icon_name)

        try:
            pos = pyautogui.locateOnScreen(icon_path, grayscale=True, confidence=0.9)
            if pos:
                pyautogui.moveTo(pyautogui.center(pos))
                pyautogui.click()
                return True
            return False
        except pyautogui.ImageNotFoundException:
            return False


    def return_to_home(self):

        # Click current position
        pyautogui.click()

        # Await as a human
        await_millis(TIME_BASE / 5)

        icon_name = "exit.png"
        icon_path = os.path.join(self.img_path, icon_name)

        try:
            pos = pyautogui.locateOnScreen(icon_path, grayscale=True, confidence=0.9)
            if pos:
                pyautogui.moveTo(pyautogui.center(pos))
                pyautogui.click()
                return True
            return False
        except pyautogui.ImageNotFoundException:
            return False


    def go_channel(self, first_channel, channel):

        x = 0
        y = 0

        # Get the screen size
        w, h = pyautogui.size()

        # Generate the coordinates of the center
        x = int(w * 0.5)
        y = h // 2

        # Check if there is a scroll to be applied
        s = channel["s-val"]
        if s > 0:
            pyautogui.moveTo(x, y)
            for _ in range(s):
                pyautogui.scroll(-10)
                time.sleep(0.00001)

        # Get the distance from the pivot image (first channel)
        icon_path = os.path.join(self.img_path, first_channel["image"])
        x = channel["x-val"]
        y = channel["y-val"]

        # Move to the place of first image in the list
        try:
            pos = pyautogui.locateOnScreen(icon_path, grayscale=True, confidence=0.9)
            if pos:
                pyautogui.moveTo(pyautogui.center(pos))
        except pyautogui.ImageNotFoundException:
            return False

        # Move left
        angle = 0
        pyautogui.moveRel(x * math.cos(angle), y * math.sin(angle))

        # Move down
        angle = math.pi / 2
        pyautogui.moveRel(x * math.cos(angle), y * math.sin(angle))

        # Click the channel
        pyautogui.click()

        return True


class Sample():

    def __init__(self, number: int, shark: Wireshark, skygo: SkyGoDesktopApp, trace: str):

        # SkyGO and Wireshark
        self.skygo = skygo
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
            self.skygo.stop()
            self.shark.stop()
            f.close()
            await_millis(TIME_BASE)
            return False

        # Start the sniffer (step 1)
        if not self.shark.start():
            return handle_error("Error on starting Wireshark")
        
        log_event("sniffer-on", origin, f)

        # Start Sky (step 2)
        if not self.skygo.start():
            return handle_error("Error on starting Sky application")
        
        log_event("skygo-on", origin, f)
        
        # Await before starting the experiment
        await_millis(TIME_BASE * 2)

        # Determine channels based on the experiment number
        channel_mapping = {
            1: PARAMETERS["italy"][:1],  # Test just a national channel
            2: PARAMETERS["globe"][:],   # Test international channels
            3: PARAMETERS["italy"][:],   # Test only national channels
            4: PARAMETERS["globe"][:3]   # Test some channels with random delay
        }
        channels = channel_mapping.get(self.number, [])

        # Start watching channels (step 3)
        if not self.skygo.jump_to_home():
            return handle_error("Error on getting channels list")
        
        # Await before watching the first channel
        await_millis(TIME_BASE)

        # Watch all channels
        for channel in channels:
            if not self.skygo.go_channel(channels[0], channel):
                return handle_error("Error on getting a channel")
            
            # Log the channel has been opened
            log_event(f"{channel['name']}-on", origin, f)
            
            # Watch the stream for a random duration between 40 and 60 seconds
            await_millis(random.randint(40, 60))
            
            # Log the channel has been closed
            log_event(f"{channel['name']}-off", origin, f)
            
            # Go back to home
            if not self.skygo.return_to_home():
                return handle_error("Error on going back")
            
            # Await before the next channel for a random duration between 5 and 15 seconds
            await_millis(random.randint(5, 15))

        # Stop Sky
        self.skygo.stop()
        log_event("skygo-off", origin, f)

        # Stop the sniffer
        self.shark.stop()
        log_event("sniffer-off", origin, f)

        # Close the file
        f.close()

        # Await before stepping into the next experiment
        await_millis(TIME_BASE)
        return True


def main(number, repetitions, interface, results_folder_name):

    # The path where results will be stored
    main_dir = os.path.join(os.getcwd(), "results", results_folder_name)

    if not os.path.exists(main_dir):
        os.makedirs(main_dir)

    # Edit here the path of Wireshark and SkyGo
    shark_exe_path = r"C:\\Program Files\\Wireshark\\tshark.exe"
    skygo_exe_path = r"C:\Users\giorg\AppData\Roaming\Sky\Sky Go\Sky Go.exe"

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
        service = SkyGoDesktopApp(exe_path=skygo_exe_path, img_path=os.path.join(os.getcwd(), "images", platform))

        # Generate a new instance of Experiment controller
        sample = Sample(number=number, shark=sniffer, skygo=service, trace=streambot_file_path)

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
    parser.add_argument('--number', type=int, default=4, choices=["1", "2", "3", "4"], help='Experiment number')
    parser.add_argument('--repetitions', type=int, default=10, help='Number of repetitions')
    parser.add_argument('--interface', type=str, default='Wi-Fi', help='Interface')

    args = parser.parse_args()

    # Run the main program
    main(number=args.number, repetitions=args.repetitions, interface=args.interface, results_folder_name="test-0")
