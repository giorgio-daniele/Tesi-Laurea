import io
import os
import re
import pandas
import math
from   constants   import *
from   collections import defaultdict

class Experiment:

    def __init__(self, wireshark_trace_file, streambot_trace_file):

        # Wireshark and Streambot trace files
        self.wireshark_trace_file: str = wireshark_trace_file
        self.streambot_trace_file: str = streambot_trace_file

        # Input file (TCP log complete)
        self.tstat_tcp_complete_file: str = None

        # Input file (UDP log complete)
        self.tstat_udp_complete_file: str = None

        # Input file (TCP log complete periodic)
        self.tstat_log_periodic_file: str = None

        # Ouput file (TCP log complete)
        self.estat_tcp_complete_file:  str = None
        self.estat_tcp_complete_frame: pandas.DataFrame = None
        
        # Output file (TCP log complete periodic)
        self.estat_tcp_log_periodic_file: str = None
        self.estat_tcp_log_periodic_frame: pandas.DataFrame = None

        # Output file (UDP log complete)
        self.estat_udp_complete_file:  str = None
        self.estat_udp_complete_frame: pandas.DataFrame = None
        
        # Streaming intervals (over TCP)
        self.streaming_intervals_tcp: list[object] = []
        # Streaming intervals (over UDP)
        self.streaming_intervals_udp: list[object] = []

    def run_tstat(self):

        # Compile Wireshark trace
        runtime_conf_file_path = os.path.join(os.getcwd(), "runtime.conf")
        os.system(f"{TSTAT_BINARY_PATH} -T {runtime_conf_file_path} {self.wireshark_trace_file} > /dev/null")

        # Generate the name of Tstat ouput directory
        tstat_dir = self.wireshark_trace_file.replace(WIRESHARK_EXT, TSTAT_EXT)

        # Loop overe all Tstat ouput
        for dir in os.listdir(tstat_dir):

            # Generate the name of the current directory
            dir_path = os.path.join(tstat_dir, dir)

            # Move all TXT files to the parent directory and remove the empty folder
            for log in os.listdir(dir_path):
                os.rename(os.path.join(dir_path, log), os.path.join(tstat_dir, log))

            # Remove the empty folder and stop here
            os.rmdir(dir_path)
            break

        # Get trace TCP log complete (input file)
        self.tstat_tcp_complete_file = os.path.join(tstat_dir, "log_tcp_complete")

        # Define output files
        self.estat_tcp_complete_file = self.wireshark_trace_file.replace(WIRESHARK_EXT, ESTAT_TCP_EXT)
        self.estat_tcp_complete_file = self.estat_tcp_complete_file.replace(WIRESHARK_PFX, ESTAT_TCP_PFX)
        
        # Generate the frame associated to the TCP log complete
        self.estat_tcp_complete_frame, self.streambot_trace_frame = estat_tcp_log_complete(
            self.tstat_tcp_complete_file,           # Tstat file (input file)
                self.streambot_trace_file,          # Streambot file (input file)
                    self.estat_tcp_complete_file)   # Estat file (output file)

        # Get trace UDP log complete (input file)
        self.tstat_udp_complete_file = os.path.join(tstat_dir, "log_udp_complete")

        # Define output files
        self.estat_udp_complete_file = self.wireshark_trace_file.replace(WIRESHARK_EXT, ESTAT_UDP_EXT)
        self.estat_udp_complete_file = self.estat_udp_complete_file.replace(WIRESHARK_PFX, ESTAT_UDP_PFX)

        # Generate the frame associated to the UDP log complete
        self.estat_udp_complete_frame = estat_udp_log_complete(
            self.tstat_udp_complete_file,           # Tstat file (input file)
                self.streambot_trace_file,          # Streambot file (input file)
                    self.estat_udp_complete_file)   # Estat file (output file)

        # Get trace TCP log periodic
        self.tstat_log_periodic_file = os.path.join(tstat_dir, "log_periodic_complete")

        # Define output files
        self.estat_tcp_log_periodic_file = self.wireshark_trace_file.replace(WIRESHARK_EXT, ESTAT_TCP_LOG_PERIODIC_EXT)
        self.estat_tcp_log_periodic_file = self.estat_tcp_log_periodic_file.replace(WIRESHARK_PFX, ESTAT_TCP_LOG_PERIODIC_PFX)

        # Generate the frame associated to the TCP log periodic
        self.estat_tcp_log_periodic_frame = estat_tcp_log_periodic(
            self.tstat_log_periodic_file,           # Tstat file (input file)
                self.streambot_trace_file,          # Streambot file (input file)
                    self.estat_tcp_log_periodic_file)   # Estat file (output file)

        # Clean all Tstat outputs
        logs = [os.path.join(tstat_dir, f) for f in os.listdir(tstat_dir)]
        for log in logs:
            os.remove(log)
        os.removedirs(tstat_dir)

    def get_streaming_intervals_over_tcp(self, channels):
        
        # Remove anything from Streambot frame that is not a channel log
        bot_frame = self.streambot_trace_frame[self.streambot_trace_frame["EVENT"].str.contains("|".join(channels))]

        # Remove anything from Estat frame (TCP) in which the token is not available
        tcp_frame = self.estat_tcp_complete_frame[self.estat_tcp_complete_frame["TOKEN"] != "NONE"]

        # Generate the list of all events associated to a streaming interval
        instants = bot_frame["FROM_ORIGIN_MS"].tolist()

        # Loop over points, by coupling ts (time start) and te (time end)
        for ts, te in zip(instants[::2], instants[1::2]):
            
            key = "TIME_ABS_START"

            # Create a slice of the TCP frame with all flows that has been started
            # within the time period Streambot confirms to be a streaming interval
            interval = tcp_frame[(tcp_frame[key] >= ts) & (tcp_frame[key] <= te)]

            # Add to views list, the previous one (if not empty)
            if len(interval) <= 0:
                continue

            # Generate a new object that is a view
            view = {}

            # Add basic information
            view["time_s"] = interval["TIME_ABS_START"].min()
            view["time_e"] = interval["TIME_ABS_START"].max()
            view["idex_s"] = interval["TIME_ABS_START"].idxmin()
            view["idex_e"] = interval["TIME_ABS_START"].idxmax()
            view["dframe"] = interval
            view["tokens"] = interval["TOKEN"].tolist() if "TOKEN" in interval.columns else []
            view["lstats"] = {}

            # Add advanced information
            keys = ["CLIENT_IP_ADDRESS", "SERVER_IP_ADDRESS", "CLIENT_L4_PORT", "SERVER_L4_PORT"]

            # Loop over all rows in this interval
            for index, row in interval.loc[:, keys].iterrows():
                
                # Isolate socket addresses by creating a tuple key
                socket_key = (row["CLIENT_IP_ADDRESS"], row["SERVER_IP_ADDRESS"], row["CLIENT_L4_PORT"], row["SERVER_L4_PORT"])

                # Select all rows that have to do with the same key
                matching_rows = self.estat_tcp_log_periodic_frame.loc[
                    (self.estat_tcp_log_periodic_frame["CLIENT_IP_ADDRESS"] == socket_key[0]) & # Filter by IP address (client)
                    (self.estat_tcp_log_periodic_frame["SERVER_IP_ADDRESS"] == socket_key[1]) & # Filter by IP address (server)
                    (self.estat_tcp_log_periodic_frame["CLIENT_L4_PORT"]    == socket_key[2]) & # Filter by L4 port (client)
                    (self.estat_tcp_log_periodic_frame["SERVER_L4_PORT"]    == socket_key[3])   # Filter by L4 port (server)
                ]

                # Associate the filtered DataFrame with the corresponding key in the view["lstats"] dictionary
                view["lstats"][socket_key] = matching_rows

            # Backup all streaming intervals
            self.streaming_intervals_tcp.append(view)



def tokenizer(record):
    
    token = ""
    proto = "PROTOCOL"

    if proto in record:

        if record[proto] == "TLS":
            if "SERVER_CNAME_CLIENT_HELLO" in record and record["SERVER_CNAME_CLIENT_HELLO"] != "-":
                token = record["SERVER_CNAME_CLIENT_HELLO"]
        elif record[proto] == "HTTP":
            if "SERVER_CNAME_HTTP_HOSTNAME" in record and record["SERVER_CNAME_HTTP_HOSTNAME"] != "-":
                token = record["SERVER_CNAME_HTTP_HOSTNAME"]

    if token == "":
        if "SERVER_CNAME_DNS_QUERY" in record and record["SERVER_CNAME_DNS_QUERY"] != "-":
            token = record["SERVER_CNAME_DNS_QUERY"]

    if token == "":
        token = "NONE"

    token = token.replace("-", ".")
    names = token.split(".")

    token = ".".join(names[-3:-1]) if len(names) >= 3 else ".".join(names)
    token = re.sub(r"\d+", "#", token)

    return token

def l7_protocol_over_tcp(record):

    name = record["PROTOCOL"]
    name = ESTAT_L7_PROTOCOL_TCP[name]

    return "NONE" if name == None else name

def estat_tcp_log_periodic(tstat_log_periodic_file: str, streambot_trace_file: str, estat_tcp_log_periodic_file: str):

    # Generate a frame from Streambot trace
    bot_frame : pandas.DataFrame = pandas.read_csv(streambot_trace_file, delimiter=STREAMBOT_TRACE_COLUMNS_DELIMITER)

    # Generate a frame from Estat UDP trace
    log_frame : pandas.DataFrame = pandas.read_csv(tstat_log_periodic_file, delimiter=TSTAT_TRACE_COLUMNS_DELIMITER)

    # Generate the values and the key by which selecting just relevant
    # features
    values  = list(ESTAT_TCP_LOG_PERIODIC_SUMMARY_COLUMNS.values())
    columns = list(ESTAT_TCP_LOG_PERIODIC_SUMMARY_COLUMNS.keys())

    # Filter the frame by selecting just relevant features
    log_frame = log_frame.iloc[:, values]
    log_frame.columns = columns

    ts = "TIME_ABS_START"

    # For each row, allign the time to the origin of Streambot trace
    log_frame.loc[log_frame[ts] != 0, ts] -= float(bot_frame.loc[0, "UNIX_TS"])

    # Write the result on disk
    log_frame.to_csv(estat_tcp_log_periodic_file, sep=TSTAT_TRACE_COLUMNS_DELIMITER, index=False, header=True)

    # Return the frame
    return log_frame

def estat_tcp_log_complete(tstat_tcp_complete_file: str, streambot_trace_file: str, estat_tcp_complete_file: str):

    # Generate a frame from Streambot trace
    bot_frame : pandas.DataFrame = pandas.read_csv(streambot_trace_file, delimiter=STREAMBOT_TRACE_COLUMNS_DELIMITER)

    # Generate a frame from Estat UDP trace
    tcp_frame : pandas.DataFrame = pandas.read_csv(tstat_tcp_complete_file, delimiter=TSTAT_TRACE_COLUMNS_DELIMITER)

    # Generate the values and the key by which selecting just relevant
    # features
    values  = list(ESTAT_TCP_SUMMARY_COLUMNS.values())
    columns = list(ESTAT_TCP_SUMMARY_COLUMNS.keys())

    # Filter the frame by selecting just relevant features
    tcp_frame = tcp_frame.iloc[:, values]
    tcp_frame.columns = columns

    tstamp_s = "TIME_ABS_START"
    tstamp_e = "TIME_ABS_END"

    # For each row, allign the time to the origin of Streambot trace
    tcp_frame.loc[tcp_frame[tstamp_s] != 0, tstamp_s] -= float(bot_frame.loc[0, "UNIX_TS"])
    tcp_frame.loc[tcp_frame[tstamp_e] != 0, tstamp_e] -= float(bot_frame.loc[0, "UNIX_TS"])

    # Generate a human readable version of protocol
    tcp_frame["PROTOCOL"] = tcp_frame.apply(l7_protocol_over_tcp, axis=1)

    datetime_s = "DATE_TIME_ABS_START"
    datetime_e = "DATE_TIME_ABS_END"

    # Generate a datetime format for the timestamps
    tcp_frame[datetime_s] = pandas.to_datetime(tcp_frame[tstamp_s])
    tcp_frame[datetime_e] = pandas.to_datetime(tcp_frame[tstamp_s])

    # Generate the token
    tcp_frame["TOKEN"] = tcp_frame.apply(tokenizer, axis=1)

    # Sort Estat dataframe by date of first packet
    tcp_frame.sort_values(by=tstamp_s, inplace=True)
    tcp_frame.reset_index(drop=True, inplace=True)
    tcp_frame.index += 1

    # Write the result on disk
    tcp_frame.to_csv(estat_tcp_complete_file, sep=TSTAT_TRACE_COLUMNS_DELIMITER, index=False, header=True)

    # Return the frame
    return tcp_frame, bot_frame

def estat_udp_log_complete(tstat_udp_complete_file: str, streambot_trace_file: str, estat_udp_complete_file: str):
    return

def tokens_profile(experiments: list[Experiment], output: str):

    # Extract all views from the experiments
    views = [view for experiment in experiments for view in experiment.streaming_intervals_tcp]

    # Count occurrences of tokens (Term Frequency - TF)
    token_counts = defaultdict(int)
    for view in views:
        for token in set(view["tokens"]):
            token_counts[token] += 1

    # Count the number of documents containing each token (Inverse Document Frequency - IDF)
    document_frequencies = defaultdict(int)
    total_documents = len(views)

    for view in views:
        seen_tokens = set()
        for token in view["tokens"]:
            if token not in seen_tokens:
                document_frequencies[token] += 1
                seen_tokens.add(token)

    # Calculate TF-IDF and save the results
    with open(output, "w") as f:
        
        # Sort the tokens by using frequncies as key
        sorted_tokens = sorted(token_counts.items(), key=lambda item: item[1], reverse=True)

        for token, count in sorted_tokens:

            # Term Frequency (TF)
            tf = count / len(views)
            
            # Inverse Document Frequency (IDF)
            idf = math.log(total_documents / document_frequencies[token])

            # Calculate TF-IDF
            tf_idf = tf * idf

            #f.write(f"{tf_idf:.4f}\t{tf:.4f}\t{token}\n")
            f.write(f"{tf:.4f}\t{token}\n")

def fetch_file_to_process(root: str) -> list[tuple[str, str]]:

    # List all files in the root directory
    files: list[str] = [os.path.join(root, f) for f in os.listdir(root)]

    # Filter Wireshark trace files
    wireshark_traces_path: list[str] = [f for f in files if os.path.isfile(f) and f.endswith(WIRESHARK_EXT) and f.startswith(os.path.join(root, WIRESHARK_PFX))]

    # Filter Streambot trace files
    streambot_traces_path: list[str] = [f for f in files if os.path.isfile(f) and f.endswith(STREAMBOT_EXT) and f.startswith(os.path.join(root, STREAMBOT_PFX))]

    # Sort and zip Wireshark and Streambot traces
    return list(zip(sorted(wireshark_traces_path), sorted(streambot_traces_path)))

def process_experiments(platform: str | None, channels: list[str]) -> list[Experiment] | None:

    # Define a list of Experiment objects
    experiments: list[Experiment] = []

    # Determine if generatin supervised or unsupervised experiments
    fold = f"supervised_experiments/{platform}" if platform else "unsupervised_experiments"
    
    # Generate the current working directory
    root = os.path.join(os.getcwd(), fold)

    # Fetch files to process
    files = fetch_file_to_process(root)
    
    # Create Experiment objects and add them to the list
    for wireshark_trace_file, streambot_trace_file in files:
        experiments.append(Experiment(wireshark_trace_file, streambot_trace_file))

    # Compile and process all experiments
    for experiment in experiments:
        experiment.run_tstat()
        experiment.get_streaming_intervals_over_tcp(channels)

    # Return the list of experiments if no platform is specified
    if platform is None:
        return experiments

    # Save experiments on disk if a platform is specified
    save_experiments_on_disk(experiments, platform)

    # Generate the profile for the specified platform
    define_platform_profile(experiments, platform)
    
    return None

def save_experiments_on_disk(experiments: list[Experiment], platform: str):

    root = os.path.join(os.getcwd(), f"streaming_intervals_{platform}")

    # Create or clean up the output directory
    if os.path.exists(root):
        for f in os.listdir(root):
            os.remove(os.path.join(root, f))
    else:
        os.mkdir(root)

    # Iterate over each experiment and save its data
    for i, experiment in enumerate(experiments):

        for view in experiment.streaming_intervals_tcp:
            path = os.path.join(root, f"sample-{i}.dat")
            with open(path, "w") as f:

                # Write each token in the view to the file
                for token in view["tokens"]:
                    f.write(f"{token}\n")

def define_platform_profile(experiments: list[Experiment], platform: str):

    profile = os.path.join(os.getcwd(), f"{platform}-profile.dat")
    if os.path.exists(profile):
        os.remove(profile)

    print(f"Computing {platform} profile...")
    tokens_profile(experiments, profile)
    print(f"Finished computing {platform} profile. Profile saved to {profile}")