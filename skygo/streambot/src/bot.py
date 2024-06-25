import random
import os
import time
import math
import subprocess
import pyautogui
import pydirectinput
import argparse

X_REL_DESKTOP = 500
X_REL_MOBILE = 150
Y_REL_DESKTOP = 70
Y_REL_MOBILE = 70
SCROLL_DESKTOP = 115
SCROLL_MOBILE = 280

CONFIGS = {
    "base": {
        "name":  "base",
        "image": "canalitv.png",
        "desktop": {
            "xrel":   0,
            "yrel":   0,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   0,
            "yrel":   0,
            "scroll": 0,
        }
    },
    "it-channels": [{
        "name":  "skytg24",
        "image": "skytg24.png",
        "desktop": {
            "xrel":   0,
            "yrel":   0,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   0,
            "scroll": 0,
        }
    }, {
        "name":  "raiuno",
        "image": "raiuno.png",
        "desktop": {
            "xrel":   0,
            "yrel":   Y_REL_DESKTOP,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE,
            "scroll": 0
        }
    }, {
        "name":  "raidue",
        "image": "raidue.png",
        "desktop": {
            "xrel":   0,
            "yrel":   Y_REL_DESKTOP * 2,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 2,
            "scroll": 0
        }
    }, {
        "name":  "raitre",
        "image": "raitre.png",
        "desktop": {
            "xrel":   0,
            "yrel":   Y_REL_DESKTOP * 3,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 3,
            "scroll": 0
        }
    }, {
        "name":  "retequattro",
        "image": "retequattro.png",
        "desktop": {
            "xrel":   0,
            "yrel":   Y_REL_DESKTOP * 4,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 4,
            "scroll": 0
        }
    }, {
        "name":  "canalecinque",
        "image": "canalecinque.png",
        "desktop": {
            "xrel":   0,
            "yrel":   Y_REL_DESKTOP * 5,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 5,
            "scroll": 0
        }
    }, {
        "name":  "italiauno",
        "iamge": "italiauno.png",
        "desktop": {
            "xrel":   0,
            "yrel":   Y_REL_DESKTOP * 6,
            "scroll": 0,
        },
        "mobile": {
            "xrel":   X_REL_MOBILE,
            "yrel":   Y_REL_MOBILE * 6,
            "scroll": 0
        }
    }],
    "eu-channels": [{
        "name":  "skysportuno",
        "image": "skysportuno.png",
        "desktop": {
            "xrel":     0,
            "yrel":     0,
            "scroll":   SCROLL_DESKTOP,
        },
        "mobile": {
            "xrel":     X_REL_MOBILE,
            "yrel":     0,
            "scroll":   SCROLL_MOBILE
        }
    }, {
        "name":  "skysportcalcio",
        "image": "skysportcalcio.png",
        "desktop": {
            "xrel":     0,
            "yrel":     Y_REL_DESKTOP,
            "scroll":   int(SCROLL_DESKTOP / 10),
        },
        "mobile": {
            "xrel":     X_REL_MOBILE,
            "yrel":     Y_REL_MOBILE,
            "scroll":   0,
        }
    }, {
        "name":  "skysporttennis",
        "image": "skysporttennis.png",
        "desktop": {
            "xrel":     0,
            "yrel":     Y_REL_DESKTOP * 2,
            "scroll":   int(SCROLL_DESKTOP / 10),
        },
        "mobile": {
            "xrel":     X_REL_MOBILE,
            "yrel":     Y_REL_MOBILE * 2,
            "scroll":   0,
        }
    }, {
        "name":  "skysportmax",
        "image": "skysportmax.png",
        "desktop": {
            "xrel":     0,
            "yrel":     Y_REL_DESKTOP * 3,
            "scroll":   int(SCROLL_DESKTOP / 10),
        },
        "mobile": {
            "xrel":     X_REL_MOBILE,
            "yrel":     Y_REL_MOBILE * 3,
            "scroll":   0,
        }
    }, {
        "name":  "skysportgolf",
        "image": "skysportgolf.png",
        "desktop": {
            "xrel":     0,
            "yrel":     Y_REL_DESKTOP * 4,
            "scroll":   int(SCROLL_DESKTOP / 10),
        },
        "mobile": {
            "xrel":     X_REL_MOBILE,
            "yrel":     Y_REL_MOBILE * 4,
            "scroll":   0,
        }
    }, {
        "name":  "skysportf1",
        "image": "skysportf1.png",
        "desktop": {
            "xrel":     0,
            "yrel":     Y_REL_DESKTOP * 5,
            "scroll":   int(SCROLL_DESKTOP / 10),
        },
        "mobile": {
            "xrel":     X_REL_MOBILE,
            "yrel":     Y_REL_MOBILE * 5,
            "scroll":   0,
        }
    }]
}

# Timing options (edit here depending on your necessities)

TIME_BASE = 10


def await_millis(ms):

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

    def __init__(self, exe_path, net_iface, out_file, pkt_limit=2500):
        self.exe_path = os.path.abspath(exe_path)
        self.out_file = os.path.abspath(out_file)
        self.pkt_limit = pkt_limit
        self.net_iface = net_iface
        self.process = None


    def start(self):
        args = [self.exe_path, "-i", self.net_iface,
                "-w", self.out_file, "-s", self.pkt_limit]
        try:
            self.process = subprocess.Popen(
                args, creationflags=subprocess.CREATE_NO_WINDOW, shell=True)
            return True
        except (OSError, ValueError) as e:
            return False
        except Exception as e:
            return False


    def stop(self):

        if self.process:
            try:
                # Use taskkill to terminate the process tree
                taskkill_cmd = f"taskkill /F /IM \"tshark.exe\""
                subprocess.run(taskkill_cmd, shell=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                pass
            finally:
                self.process = None


class SkyGo():

    def exit_desktop(self):

        if self.process:
            try:
                # Use taskkill to terminate the process tree
                taskkill_cmd = f"taskkill /F /IM \"Sky Go.exe\""
                subprocess.run(taskkill_cmd, shell=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                pass
            finally:
                self.process = None


    def exit_mobile(self):

        # Do ALT + S
        pydirectinput.keyDown("alt")
        pydirectinput.press("s")
        pydirectinput.keyUp("alt")

        # Await as a human
        await_millis(TIME_BASE / 5)

        # Move the cursor in the middle
        w, h = pyautogui.size()
        # Get the center
        x = int(w // 2)
        y = int(h // 2)
        pyautogui.mouseDown(x, y)

        # Move down
        angle = math.pi / 2
        steps = 240
        x = steps * math.cos(angle)
        y = steps * math.sin(angle)
        pyautogui.moveRel(x, y)

        # Click the current position
        pyautogui.click()


    def __init__(self, exe_path, platform, img_path):

        self.exe_path = exe_path
        self.platform = platform
        self.img_path = img_path
        self.process = None


    def start(self):

        if self.platform == "desktop":
            args = [self.exe_path]
            try:
                self.process = subprocess.Popen(
                    args, creationflags=subprocess.CREATE_NO_WINDOW, shell=True)
                return True
            except (OSError, ValueError) as e:
                return False
            except Exception as e:
                return False

        if self.platform == "mobile":
            return True

        return False


    def stop(self):

        if self.platform == "desktop":
            self.exit_desktop()

        if self.platform == "mobile":
            self.exit_mobile()


    def go_channels_list(self):

        icon_name = CONFIGS["base"]["image"]
        icon_path = os.path.join(self.img_path, icon_name)

        try:
            pos = pyautogui.locateOnScreen(
                icon_path, grayscale=True, confidence=0.9)
            if pos:
                pyautogui.moveTo(pyautogui.center(pos))
                pyautogui.click()
                return True
            return False
        except pyautogui.ImageNotFoundException:
            return False


    def go_back(self):

        if self.platform == "desktop":

            # Click current position
            pyautogui.click()

            # Await as a human
            await_millis(TIME_BASE / 5)

            icon_name = "exit.png"
            icon_path = os.path.join(self.img_path, icon_name)

            try:
                pos = pyautogui.locateOnScreen(
                    icon_path, grayscale=True, confidence=0.9)
                if pos:
                    pyautogui.moveTo(pyautogui.center(pos))
                    pyautogui.click()
                    return True
                return False
            except pyautogui.ImageNotFoundException:
                return False

        if self.platform == "mobile":

            # Just use shortcut from scrcpy
            pyautogui.rightClick()
            return True

        return False


    def go_channel(self, first_channel, channel):

        x = 0
        y = 0
        w, h = pyautogui.size()

        # Manage the scroll (if any)
        if self.platform == "mobile":
            x = int(w * 0.2)
            y = h // 2

        if self.platform == "desktop":
            x = int(w * 0.5)
            y = h // 2

        s = channel[self.platform]["scroll"]
        if s > 0:
            pyautogui.moveTo(x, y)
            for _ in range(s):
                pyautogui.scroll(-10)
                time.sleep(0.00001)

        # Get the distance from the pivot image (first channel)
        icon_path = os.path.join(self.img_path, first_channel["image"])
        x = channel[self.platform]["xrel"]
        y = channel[self.platform]["yrel"]

        try:
            pos = pyautogui.locateOnScreen(
                icon_path, grayscale=True, confidence=0.9)
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

    def __init__(self, number: int, device: str, shark: Wireshark, skygo: SkyGo, trace: str):

        # SkyGO and Wireshark
        self.skygo = skygo
        self.shark = shark

        # Experiment settings
        self.number = number
        self.device = device

        # Trace file
        self.trace = trace

    def start_experiment(self):

        channels = []

        # Open in write mode the file (Streambot trace)
        f = open(self.trace, "w")

        # Write the origin of the experiment
        origin = log_origin(f)

        # Start the sniffer
        if not self.shark.start():
            print("Error on starting Wireshark")

            # End
            f.close()

            # Await before stepping into the next experiment
            await_millis(TIME_BASE)
            return False

        log_event("sniffer-on", origin, f)

        # Start Sky
        if not self.skygo.start():

            print("Error on starting Sky application")
            self.shark.stop()

            # End
            f.close()

            # Await before stepping into the next experiment
            await_millis(TIME_BASE)
            return False

        log_event("skygo-on", origin, f)

        # Await before starting the experiment
        await_millis(TIME_BASE * 2)

        if self.number == 1:
            # Test just a national channel
            channels = CONFIGS["it-channels"][:1]
        elif self.number == 2:
            # Test international channels
            channels = CONFIGS["eu-channels"][:]
        elif self.number == 3:
            # Test only national channels
            channels = CONFIGS["it-channels"][:]
        elif self.number == 4:
            # Test some channels with random delay
            channels = CONFIGS["eu-channels"][:3]

        # Start watching channels
        if not self.skygo.go_channels_list():

            print("Error on getting channels list")
            self.skygo.stop()
            self.shark.stop()

            # End
            f.close()

            # Await before stepping into the next experiment
            await_millis(TIME_BASE)
            return False

        # Await before watching the first channel
        await_millis(TIME_BASE)

        # Watch all channels
        for channel in channels:

            if not self.skygo.go_channel(channels[0], channel):

                print("Error on getting a channel")
                self.skygo.stop()
                self.shark.stop()

                # End
                f.close()

                # Await before stepping into the next experiment
                await_millis(TIME_BASE)
                return False

            # Log the channel has been opened
            log_event(f"{channel["name"]}-on", origin, f)

            # Watch the stream (for at least 40 minutes)
            duration = random.randint(40, 60)
            await_millis(duration)

            # Log the channel has been closed
            log_event(f"{channel["name"]}-off", origin, f)

            # Go back
            if not self.skygo.go_back():

                print("Error on going back")
                self.skygo.stop()
                self.shark.stop()

                # End
                f.close()

                # Await before stepping into the next experiment
                await_millis(TIME_BASE)
                return False

            # Await before the next channel
            duration = random.randint(5, 10)
            await_millis(duration)

        # Stop Sky
        self.skygo.stop()
        log_event("skygo-off", origin, f)

        # Stop the sniffer
        self.shark.stop()
        log_event("sniffer-off", origin, f)

        # End
        f.close()

        # Await before stepping into the next experiment
        await_millis(TIME_BASE)
        return True


def main(number, repetitions, platform, interface, results_folder_name):

    # The path where results will be stored
    main_dir = os.path.join(os.getcwd(), "results", results_folder_name)

    if not os.path.exists(main_dir):
        os.makedirs(main_dir)

    # Edit here the path of Wireshark and SkyGo
    shark_exe_path = r"C:\\Program Files\\Wireshark\\tshark.exe"
    skygo_exe_path = r"C:\Users\giorg\AppData\Roaming\Sky\Sky Go\Sky Go.exe"

    for i in range(repetitions):

        print(f"{'_' * 100}")
        print(f"Running experiment {number}")
        print(f"\tIteration n° = {i + 1}")

        # Define the ouput file for Wireshark
        wireshark_file_path = os.path.join(main_dir, f"wireshark_trace-{i}.pcap")

        # Define the output file for Streambot
        streambot_file_path = os.path.join(main_dir, f"streambot_trace-{i}.csv")

        images_path = os.path.join(os.getcwd(), "images", platform)

        # Generate a new instance of Wireshark application conteoller
        sniffer = Wireshark(exe_path=shark_exe_path, net_iface=interface,
                            out_file=wireshark_file_path, pkt_limit="2500")
        
        # Generate a new instance of SkyGo application controller
        service = SkyGo(exe_path=skygo_exe_path,
                        platform=platform, img_path=images_path)

        # Generate a new instance of Experiment controller
        sample = Sample(number=number, 
                            device=platform, shark=sniffer, skygo=service, trace=streambot_file_path)

        if sample.start_experiment():
            print("\t---> Experiment has success")

        else:
            print("\t---> Experiment has failed")

            # Remove file
            os.remove(wireshark_file_path)
            os.remove(streambot_file_path)

        print(f"{'_' * 100}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Run experiments with specified parameters.')
    parser.add_argument('--number', type=int, default=4,
                        choices=["1", "2", "3", "4"], help='Experiment number')
    parser.add_argument('--repetitions', type=int,
                        default=10, help='Number of repetitions')
    parser.add_argument('--platform', type=str, default='desktop',
                        choices=['desktop', 'mobile'], help='Platform type')
    parser.add_argument('--interface', type=str,
                        default='Wi-Fi', help='Interface')

    args = parser.parse_args()

    # Run the main program
    main(number=args.number, repetitions=args.repetitions,
         platform=args.platform, interface=args.interface, results_folder_name="test-0")
