import pandas
import os

from lib import Experiment
from lib import process_experiments


def compute_covering_index(tokens: list[str], hot_tokens: dict[str, float]):

    max = 0
    for token, value in hot_tokens.items():
        max += value

    score = 0
    for token in tokens:
        if token in hot_tokens:
            score += hot_tokens[token]
    return (score / max) * 100


# Define your constants
DELTA = pandas.Timedelta(seconds=3)
LIMIT = pandas.Timedelta(seconds=60 * 10)

class ViewsProcessor:

    def __init__(self, frame: pandas.DataFrame, streambot_trace_file: str, platform_profile: str, delta: pandas.Timedelta, limit: int, minimum: int, threshold: float=50.0):
        
        # The dataframe to be processed (input)
        self.frame = frame
        
        # The path of the platform profile to be used (input)
        self.platform_profile = platform_profile

        # The Streambot trace to be used (input)
        self.streambot_trace_file = streambot_trace_file

        # Hyperparameters
        self.minimum = minimum    # The minimum probability of a token to be considered as frequent
        self.delta = delta        # The minimum time interval between two consecutive frequent tokens
        self.limit = limit        # The maximum window size
        self.treshold = threshold # The score to be classified as POSITIVE

        # The windows that have been generated by the algorithm
        self.raw_windows: list[tuple] = []
        self.lab_windows: list[tuple] = []
        self.cls_windows: list[tuple] = []


    def print_raw_windows(self):

        if len(self.raw_windows) == 0:
            print("\tNo raw windows")
            return

        for w_ts, w_te, window in self.raw_windows:

            print(f"[{w_ts} - {w_te}]")
            print()
            print(window)
            print("-" * 50)

    def print_labeled_windows(self):

        if len(self.lab_windows) == 0:
            print("No labeled windows")
            return

        for w_ts, w_te, window, label in self.lab_windows:
            print(f"[{w_ts} - {w_te}] | LAB = {label}")
            print()
            print(window)
            print("-" * 50)

    def print_classified_windows(self):

        if len(self.cls_windows) == 0:
            print("\tNo classified windows")
            return

        for w_ts, w_te, window, label, result in self.cls_windows:
            print(f"[{w_ts} - {w_te}] | LAB = {label} CLS = {result}")
            print()
            print(window)
            print("-" * 50)


    def generate_windows(self):

        all_tokens = {}
        hot_tokens = {}

        i, horizon = 0, None

        windows = []
        
        # Read from platform profile all tokens and their frequencies
        with open(self.platform_profile, "r") as file:

            for line in file:
                v, t = line.strip().split("\t")

                # Add to all tokens the current one
                all_tokens[t] = float(v)

                # Add this token to the dictionary of hot tokens
                if float(v) >= self.minimum:
                    hot_tokens[t] = float(v)

        # Convert timestamp column to pandas datetime objects
        self.frame["DT_FP"] = pandas.to_datetime(self.frame["DT_FP"])

        # Extract and sort hotspots
        hotspots = []

        for index, row in self.frame.iterrows():
            if row["TOKEN"] in hot_tokens:
                hotspots.append(row["DT_FP"])

        # Sort the resulting list
        hotspots = sorted(hotspots)

        while i < len(hotspots):
            
            # Generate a window centered on the current hotspot
            ts, tn, te = hotspots[i] - self.delta, hotspots[i], hotspots[i] + self.delta

            # Manage overlapping windows
            ts = max(ts, horizon) if horizon else ts
            i += 1

            while i < len(hotspots) and hotspots[i] <= te:
                te = hotspots[i] + self.delta
                i += 1
                if te - tn > self.limit:
                    break

            # Slice the current window and append it if non-empty
            window = self.frame[(self.frame["DT_FP"] >= ts) & (self.frame["DT_FP"] <= te)]
            
            if len(window) > 0:
                windows.append((window.index[0], window.index[-1], window))

            # Update the horizon
            horizon = te

        self.raw_windows = windows


    def label_windows_3a(self, intervals: list[tuple[int, int]]):

        visited = set()

        # Loop over all windows, selecting the timestamps of the first and last occurences,
        # alongside the indeces of such elements
        for w_ts, w_te, window in self.raw_windows:
            
            match = False

            # Loop over all intervals
            for i_ts, i_te in intervals:

                # Check if there an intersection between the window and the current interval
                if max(w_ts, i_ts) <= min(w_te, i_te):

                    # Check if this interval has already been marked intersected with
                    # another window in the past
                    
                    if (i_ts, i_te) in visited:
                        item = (w_ts, w_te, window, "NEGATIVE")
                        self.lab_windows.append(item)
                    else:
                        item = (w_ts, w_te, window, "POSITIVE")
                        self.lab_windows.append(item)
                        visited.add((i_ts, i_te))

                    # We find an intersection
                    match = True
                    break

            if not match:
                item = (w_ts, w_te, window, "NEGATIVE")
                self.lab_windows.append(item)


    def label_windows_3b(self, intervals: list[tuple[int, int]]):


        # Loop over all windows, selecting the timestamps of the first and last occurences,
        for w_ts, w_te, window in self.raw_windows:
            
            match = False

            # Loop over all intervals
            for i_ts, i_te in intervals:

                # Check if there an intersection between the window and the current interval
                if max(w_ts, i_ts) <= min(w_te, i_te):

                    item = (w_ts, w_te, window, "POSITIVE")
                    self.lab_windows.append(item)

                    # We find an intersection
                    match = True
                    break

            if not match:
                item = (w_ts, w_te, window, "NEGATIVE")
                self.lab_windows.append(item)


    def classify_windows(self):

        all_tokens = {}
        hot_tokens = {}
        
        # Read from platform profile all tokens and their frequencies
        with open(self.platform_profile, "r") as file:

            for line in file:
                v, t = line.strip().split("\t")

                # Add to all tokens the current one
                all_tokens[t] = float(v)

                # Add this token to the dictionary of hot tokens
                if float(v) >= self.minimum:
                    hot_tokens[t] = float(v)

        # Loop over all windows
        for w_ts, w_te, window, label in self.lab_windows:

            # Compute the score
            score = compute_covering_index(window["TOKEN"].tolist(), hot_tokens)
            
            if label == "POSITIVE":

                label = "POSITIVE"

                if score >= self.treshold:
                    item = (w_ts, w_te, window, label, "POSITIVE")
                    self.cls_windows.append(item)
                
                if score < self.treshold:
                    item = (w_ts, w_te, window, label, "NEGATIVE")
                    self.cls_windows.append(item)

            if label == "NEGATIVE":

                label = "NEGATIVE"

                if score >= self.treshold:
                    item = (w_ts, w_te, window, label, "POSITIVE")
                    self.cls_windows.append(item)
                
                if score < self.treshold:
                    item = (w_ts, w_te, window, label, "NEGATIVE")
                    self.cls_windows.append(item)

if __name__ == "__main__":

    desktop_profile = os.path.join(os.getcwd(), "desktop-profile.dat")
    mobile_profile  = os.path.join(os.getcwd(), "mobile-profile.dat")

    experiments: list[Experiment] = process_experiments(None, ["tg", "rai", "quattro", "cinque", "sport"])

    for experiment in experiments:

        # Inputs
        tcp_complete_frame = experiment.estat_tcp_complete_frame
        platform_profile = desktop_profile
        streambot_trace_file = experiment.streambot_trace_file

        # Hyperparameters
        delta = DELTA
        limit = LIMIT
        minimum = 0.86

        # Generate a new processor
        processor: ViewsProcessor = ViewsProcessor(tcp_complete_frame, streambot_trace_file, platform_profile, delta, limit, minimum)

        # Generate the windows
        processor.generate_windows()

        # Print the generated windows
        processor.print_raw_windows()

        intervals = [(view["first_row"], view["last_row"]) for view in experiment.views]

        # Label the windows
        processor.label_windows_3a(intervals)

        # Classify the windows
        processor.classify_windows()

        print(f"EXPERIMENT")
        print("-" * 100)

        # Print the output
        processor.print_classified_windows()

        print("-" * 100)
        print()


