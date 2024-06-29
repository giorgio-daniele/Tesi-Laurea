import io
import os
import re
import pandas
import math
from   constants   import *
from   collections import defaultdict

class StreamingInterval:

    def __init__(self, 
                 min_stamp: int, max_stamp: int, 
                 min_index: int, max_index: int, 
                 interval: pandas.DataFrame, tokens: list[str], statistics: pandas.DataFrame):
        
        self.min_stamp: int = min_stamp
        self.max_stamp: int = max_stamp

        self.min_index: int = min_index
        self.max_index: int = max_index

        self.interval:   pandas.DataFrame = interval
        self.statistics: pandas.DataFrame = statistics
        
        self.tokens: list[str] = tokens

    def __str__(self) -> str:
        print(', '.join(self.tokens))
        return ', '.join(self.tokens)

class Experiment:

    def __init__(self, wireshark_trace_file, streambot_trace_file):

        # Wireshark trace file
        self.npcap_log_complete_file: str = wireshark_trace_file

        # Streambot trace file
        self.smbot_log_activity_file: str = streambot_trace_file

        # Input file (TCP log complete)
        self.tstat_tcp_complete_file: str = None

        # Input file (UDP log complete)
        self.tstat_udp_complete_file: str = None

        # Input file (TCP log complete periodic)
        self.tstat_log_periodic_file: str = None

        # Ouput file (TCP log complete)
        self.estat_tcp_complete_file: str = None
        
        # Output file (UDP log complete)
        self.estat_udp_complete_file: str = None

        # Output file (TCP log periodic)
        self.estat_log_periodic_file: str = None
        
        # Dataframes
        self.estat_tcp_complete_frame: pandas.DataFrame = None
        self.estat_udp_complete_frame: pandas.DataFrame = None
        self.estat_log_periodic_frame: pandas.DataFrame = None
        self.smbot_log_activity_frame: pandas.DataFrame = None
        
        # Streaming intervals (over TCP)
        self.streaming_intervals_tcp: list[StreamingInterval] = []
        # Streaming intervals (over UDP)
        self.streaming_intervals_udp: list[StreamingInterval] = []

    def run_tstat(self):

        # Compile Wireshark by using Tstat
        os.system(f"{TSTAT_BINARY_PATH} -T {os.path.join(os.getcwd(), 'runtime.conf')} {self.npcap_log_complete_file} > /dev/null")

        # Generate the root directory path for Tstat outputs
        root: str = self.npcap_log_complete_file.replace(WIRESHARK_EXT, TSTAT_EXT)

        # Generate all sub-directories
        sub_dirs: list[str] = [os.path.join(root, dir) for dir in os.listdir(root)]

        # For each sub-directory, generate the list of files
        sub_dirs_all_files : list[str] = [[os.path.join(dir, f) for f in os.listdir(dir)] for dir in sub_dirs]
        
        # Select just the files to be processed
        targets = ['log_tcp_complete', 'log_udp_complete', 'log_periodic_complete']
        sub_dirs_files: list[str] = [[f for f in files if any(key in f for key in targets)] for files in sub_dirs_all_files]

        # Loop over sub-directories, but just take the first one
        for file in sub_dirs_files[0]:

            # Case log TCP complete
            if file.endswith(targets[0]):
                self.tstat_tcp_complete_file = file
                self.estat_tcp_complete_file = self.npcap_log_complete_file.replace(WIRESHARK_EXT, ESTAT_TCP_EXT)
                self.estat_tcp_complete_file = self.estat_tcp_complete_file.replace(WIRESHARK_PFX, ESTAT_TCP_PFX)

            # Case log UDP complete
            if file.endswith(targets[1]):
                self.tstat_udp_complete_file = file
                self.estat_udp_complete_file = self.npcap_log_complete_file.replace(WIRESHARK_EXT, ESTAT_UDP_EXT)
                self.estat_udp_complete_file = self.estat_udp_complete_file.replace(WIRESHARK_PFX, ESTAT_UDP_PFX)
                
            # Case log TCP periodic
            if file.endswith(targets[2]):
                self.tstat_log_periodic_file = file
                self.estat_log_periodic_file = self.npcap_log_complete_file.replace(WIRESHARK_EXT, ESTAT_TCP_LOG_PERIODIC_EXT)
                self.estat_log_periodic_file = self.estat_log_periodic_file.replace(WIRESHARK_PFX, ESTAT_TCP_LOG_PERIODIC_PFX)

        # Generate Streambot frame
        self.smbot_log_activity_frame: pandas.DataFrame = streamobot_trace_frame(self.smbot_log_activity_file)

        # Generate TCP log complete frame
        print(f"Generating TCP log complete frame for {self.npcap_log_complete_file}")
        self.estat_tcp_complete_frame: pandas.DataFrame = tcp_log_complete(self.tstat_tcp_complete_file, self.smbot_log_activity_frame, self.estat_tcp_complete_file)   

        # Generate UDP log complete frame
        print(f"Generating UDP log complete frame for {self.npcap_log_complete_file}")
        self.estat_udp_complete_frame: pandas.DataFrame = udp_log_complete(self.tstat_udp_complete_file, self.smbot_log_activity_frame, self.estat_udp_complete_file) 

        # Generate TCP log periodic frame
        print(f"Generating TCP log periodic frame for {self.npcap_log_complete_file}")
        self.estat_log_periodic_frame: pandas.DataFrame = tcp_log_periodic(self.tstat_log_periodic_file, self.smbot_log_activity_frame, self.estat_log_periodic_file) 

    def isolate_streaming_intervals_tcp(self, channels: list[str]):

        # Remove any action which is not related to a streaming interval
        bot_frame = self.smbot_log_activity_frame[self.smbot_log_activity_frame["EVENT"].str.contains("|".join(channels))]

        # Remove any TCP flows for which a token is not available
        tcp_frame = self.estat_tcp_complete_frame[self.estat_tcp_complete_frame["TOKEN"] != "NONE"]

        # Generate the list of checkpoints for each action
        checkpoints = bot_frame["FROM_ORIGIN_MS"].tolist()

        # Loop over points, by coupling ts (time start) and te (time end)
        for ts, te in zip(checkpoints[::2], checkpoints[1::2]):
            
            # Slice the original frame and isolate all flows that have been started within the streaming interval
            interval: pandas.DataFrame = tcp_frame[(tcp_frame["TIME_ABS_BEGIN"] >= ts) & (tcp_frame["TIME_ABS_BEGIN"] <= te)]

            # Add to views list, the previous one (if not empty)
            if len(interval) <= 0:
                continue

            # Add advanced information
            keys = ["CLIENT_IP_ADDRESS", "SERVER_IP_ADDRESS", "CLIENT_L4_PORT", "SERVER_L4_PORT"]

            # Loop over all flows in the interval: for each flow, define the couple 
            # of socket (the client and the server addresses)
            for _, row in interval.loc[:, keys].iterrows():
                
                # Isolate socket addresses by creating a tuple key
                key = (row["CLIENT_IP_ADDRESS"], row["SERVER_IP_ADDRESS"], row["CLIENT_L4_PORT"], row["SERVER_L4_PORT"])

                # Select all rows that have to do with the same key
                statistics = self.estat_log_periodic_frame.loc[
                    (self.estat_log_periodic_frame["CLIENT_IP_ADDRESS"] == key[0]) &
                    (self.estat_log_periodic_frame["SERVER_IP_ADDRESS"] == key[1]) & 
                    (self.estat_log_periodic_frame["CLIENT_L4_PORT"] == key[2])    & 
                    (self.estat_log_periodic_frame["SERVER_L4_PORT"] == key[3])]

                # Generate a new streaming interval as an object
                streaming_interval = StreamingInterval(
                    min_stamp=interval["TIME_ABS_BEGIN"].min(),
                    max_stamp=interval["TIME_ABS_BEGIN"].max(),
                    min_index=interval["TIME_ABS_BEGIN"].idxmin(),
                    max_index=interval["TIME_ABS_BEGIN"].idxmax(),
                    interval=interval, tokens=interval["TOKEN"].tolist() if "TOKEN" in interval.columns else [], statistics=statistics)

            # Save the streaming interval
            self.streaming_intervals_tcp.append(streaming_interval)

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

def streamobot_trace_frame(streambot_trace_file: str) -> pandas.DataFrame:

    return pandas.read_csv(streambot_trace_file, delimiter=STREAMBOT_TRACE_COLUMNS_DELIMITER)

def tcp_log_periodic(tstat_log_periodic_file: str, smbot_log_activity_frame: pandas.DataFrame, estat_tcp_log_periodic_file: str):

    # Define the time origin (the one from which Streambot has started)
    bot_otime = float(smbot_log_activity_frame.loc[0, "UNIX_TS"])

    # Generate the TCP log periodic frame
    log_frame: pandas.DataFrame = pandas.read_csv(tstat_log_periodic_file, delimiter=TSTAT_TRACE_COLUMNS_DELIMITER)

    # Select just interesting columns
    log_frame = log_frame.iloc[:, list(ESTAT_TCP_LOG_PERIODIC_SUMMARY_COLUMNS.values())]
    log_frame.columns = list(ESTAT_TCP_LOG_PERIODIC_SUMMARY_COLUMNS.keys())

    # For each row, allign the time to the origin of Streambot trace
    log_frame["TIME_ABS_BEGIN"] -= bot_otime

    # Write the result on disk
    log_frame.to_csv(estat_tcp_log_periodic_file, sep=TSTAT_TRACE_COLUMNS_DELIMITER, index=False, header=True)

    # Return the frame
    return log_frame

def tcp_log_complete(tstat_tcp_complete_file: str, smbot_log_activity_frame: pandas.DataFrame, estat_tcp_complete_file: str):

    # Define the time origin (the one from which Streambot has started)
    bot_otime = float(smbot_log_activity_frame.loc[0, "UNIX_TS"])

    # Generate the TCP log complete frame
    tcp_frame: pandas.DataFrame = pandas.read_csv(tstat_tcp_complete_file, delimiter=TSTAT_TRACE_COLUMNS_DELIMITER)

    # Select just interesting columns
    tcp_frame = tcp_frame.iloc[:, list(ESTAT_TCP_SUMMARY_COLUMNS.values())]
    tcp_frame.columns = list(ESTAT_TCP_SUMMARY_COLUMNS.keys())

    # For each row, allign the time to the origin of Streambot trace
    tcp_frame["TIME_ABS_BEGIN"] -= bot_otime
    tcp_frame["TIME_ABS_ENDUP"] -= bot_otime

    # Generate a human readable version of protocol
    tcp_frame["PROTOCOL"] = tcp_frame.apply(l7_protocol_over_tcp, axis=1)

    # Generate a datetime format for the timestamps
    tcp_frame["DATE_TIME_ABS_BEGIN"] = pandas.to_datetime(tcp_frame["TIME_ABS_BEGIN"])
    tcp_frame["DATE_TIME_ABS_ENDUP"] = pandas.to_datetime(tcp_frame["TIME_ABS_ENDUP"])

    # Generate the token
    tcp_frame["TOKEN"] = tcp_frame.apply(tokenizer, axis=1)

    # Sort Estat dataframe by date of first packet
    tcp_frame.sort_values(by="TIME_ABS_BEGIN", inplace=True)
    tcp_frame.reset_index(drop=True, inplace=True)
    tcp_frame.index += 1

    # Save the result on disk
    tcp_frame.to_csv(estat_tcp_complete_file, sep=TSTAT_TRACE_COLUMNS_DELIMITER, index=False, header=True)

    # Return the frame
    return tcp_frame

def udp_log_complete(tstat_udp_complete_file: str, streambot_trace_file: str, estat_udp_complete_file: str):
    return

def tokens_profile(streaming_intervals: list[StreamingInterval], output: str):

    # Count occurrences of tokens (Term Frequency - TF)
    token_counts = defaultdict(int)
    for streaming_interval in streaming_intervals:
        for token in set(streaming_interval.tokens):
            token_counts[token] += 1

    # Count the number of documents containing each token (Inverse Document Frequency - IDF)
    document_frequencies = defaultdict(int)
    total_documents = len(streaming_intervals)

    for streaming_interval in streaming_intervals:
        seen_tokens = set()
        for token in streaming_interval.tokens:
            if token not in seen_tokens:
                document_frequencies[token] += 1
                seen_tokens.add(token)

    # Calculate TF-IDF and save the results
    with open(output, "w") as f:
        
        # Sort the tokens by using frequncies as key
        sorted_tokens = sorted(token_counts.items(), key=lambda item: item[1], reverse=True)

        for token, count in sorted_tokens:

            # Term Frequency (TF)
            tf = count / len(streaming_intervals)
            
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

    # Determine if generatin supervised or unsupervised experiments
    fold = f"supervised_experiments/{platform}" if platform else "unsupervised_experiments"
    
    # Generate the current working directory
    root = os.path.join(os.getcwd(), fold)

    # Fetch files to process
    files = fetch_file_to_process(root)
    
    # Create Experiment objects and add them to the list
    experiments: list[Experiment] = [Experiment(wireshark_trace_file, streambot_trace_file) for wireshark_trace_file, streambot_trace_file in files]

    # Compile and process all experiments
    for experiment in experiments:
        experiment.run_tstat()
        experiment.isolate_streaming_intervals_tcp(channels=channels)

    # Return the list of experiments if no platform is specified
    if platform is None:
        return experiments
    
    streaming_intervals: list[StreamingInterval] = []
    for experiment in experiments:
        streaming_intervals.extend(experiment.streaming_intervals_tcp)
    
    # Save TCP streaming interval on file
    save_tcp_streaming_intervals(streaming_intervals=streaming_intervals, platform=platform)

    # Save TCP streaming tokens on file
    save_tcp_streaming_tokens(streaming_intervals=streaming_intervals, platform=platform)
    
    return None

def save_tcp_streaming_intervals(streaming_intervals: list[StreamingInterval], platform: str):

    # Generate the output directory path
    root = os.path.join(os.getcwd(), f"streaming_intervals_{platform}")

    if os.path.exists(root):
        for f in os.listdir(root):
            os.remove(os.path.join(root, f))
    else:
        os.mkdir(root)

    for i, streaming_interval in enumerate(streaming_intervals):
        
        # Generate the path of the current streaming_interval
        path = os.path.join(root, f"sample-{i}.dat")

        with open(path, "w") as f:
            for token in streaming_interval.tokens:
                f.write(f"{token}\n")

def save_tcp_streaming_tokens(streaming_intervals: list[StreamingInterval], platform: str):

    # Generate the path of the output file
    profile = os.path.join(os.getcwd(), f"{platform}-profile.dat")

    # Delete any previous output if it exists
    if os.path.exists(profile):
        os.remove(profile)

    # Generate the tokens probability profile for this platform
    print(f"Computing {platform} profile...")
    tokens_profile(streaming_intervals=streaming_intervals, output=profile)
    print(f"Finished computing {platform} profile. Profile saved to {profile}")