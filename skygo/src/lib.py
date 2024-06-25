from collections import defaultdict
import os
import re
import pandas
import math

# Estat extensions and prefixes
ESTAT_TCP_EXT = ".csv"
ESTAT_TCP_PFX = "tcp_trace"

ESTAT_UDP_EXT = ".csv"
ESTAT_UDP_PFX = "udp_trace"

# Tstat extensions and prefixes
TSTAT_EXT = ".pcap.out"
TSTAT_PFX = "wireshark_trace"

# Wireshark extensions and prefixes
WIRESHARK_PFX = "wireshark_trace"
WIRESHARK_EXT = ".pcap"
# Streambot extensions and prefixes
STREAMBOT_EXT = ".csv"
STREAMBOT_PFX = "streambot_trace"

PROTOCOLS = {
    0:      "Unknown",
    1:      "HTTP",
    2:      "RTSP",
    4:      "RTP",
    8:      "ICY",
    16:     "RTCP",
    32:     "MSN",
    64:     "YMSG",
    128:    "XMPP",
    256:    "P2P",
    512:    "SKYPE",
    1024:   "SMTP",
    2048:   "POP3",
    4096:   "IMAP4",
    8192:   "TLS",
    16384:  "ED2K",
    32768:  "SSH",
    65536:  "RTMP",
    131072: "MSE/PE",
}

TSTAT_COLUMNS = {
    "CL_IP": 0,     # CLIENT_IP
    "SV_IP": 14,    # SERVER_IP
    "CL_PR": 1,     # CLIENT_PORT
    "SV_PR": 15,    # SERVER_PORT
    "UP_BY": 8,     # UPLOADED_BYTES
    "DW_BY": 22,    # DWLOADED_BYTES
    "TS_FP": 28,    # TSTAMP_FIRST_PACKET
    "TS_LP": 29,    # TSTAMP_LEAST_PACKET
    "CN_CL": 115,   # CNAME_CLIENT_HELLO
    "CN_SV": 116,   # CNAME_SERVER_HELLO
    "CN_DQ": 126,   # CNAME_DNS_QUERY
    "HT_HN": 130,   # HTTP_HOSTANAME
    "PROTO": 41,    # PROTOCOL
}

# Delimiters
BOT_DEL = "\t"
TST_DEL = " "

# Binaries
TSTAT_PATH = "/usr/local/bin/tstat"


class Experiment:

    def __init__(self, wireshark_trace_file, streambot_trace_file):

        # Wireshark and Streambot trace files
        self.wireshark_trace_file: str = wireshark_trace_file
        self.streambot_trace_file: str = streambot_trace_file

        # Ouput file (TCP log complete)
        self.estat_tcp_complete_file:  str = None
        self.estat_tcp_complete_frame: pandas.DataFrame = None

        # Output file (UDP log complete)
        self.estat_udp_complete_file:  str = None
        self.estat_udp_complete_frame: pandas.DataFrame = None
        
        # Input file (TCP log complete)
        self.tstat_tcp_complete_file: str = None

        # Input file (UDP log complete)
        self.tstat_udp_complete_file: str = None
        
        # Estat dataframe
        self.estat_tcp_complete_frame: pandas.DataFrame = None

        # Views
        self.views: list[object] = []


    def __str__(self):
        
        text = f"""Material:
        Wireshark Trace = {self.wireshark_trace_file}
        Streambot Trace = {self.streambot_trace_file}
        """
        return text


    def tstat_wireshark_trace(self):

        # Compile Wireshark trace
        os.system(f"{TSTAT_PATH} {self.wireshark_trace_file} > /dev/null")

        # Generate the name of Tstat ouput directory
        tstat_out_dir = self.wireshark_trace_file.replace(WIRESHARK_EXT, TSTAT_EXT)

        # Loop overe all Tstat ouput
        for dir in os.listdir(tstat_out_dir):

            # Generate the name of the current directory
            dir_path = os.path.join(tstat_out_dir, dir)

            # Loop over TXT documents
            for log in os.listdir(dir_path):

                # Move all TXT files into the parent directory
                old_path = os.path.join(dir_path, log)
                new_path = os.path.join(tstat_out_dir, log)
                os.rename(old_path, new_path)
            
            # Remove the empty folder
            os.rmdir(dir_path)

            # Stop here: do not process next following directories
            break

        # Get trace TCP log complete (input file)
        self.tstat_tcp_complete_file = os.path.join(tstat_out_dir, "log_tcp_complete")

        # Get trace UDP log complete (input file)
        self.tstat_udp_complete_file = os.path.join(tstat_out_dir, "log_udp_complete")

        # Generate the frame and the file trace for TCP (output file)
        self.estat_tcp_complete_file = self.wireshark_trace_file.replace(WIRESHARK_EXT, ESTAT_TCP_EXT)
        self.estat_tcp_complete_file = self.estat_tcp_complete_file.replace(WIRESHARK_PFX, ESTAT_TCP_PFX)
        
        # Generate the frame associated to the TCP log complete
        self.estat_tcp_complete_frame, self.streambot_trace_frame = etstat_tcp_complete(
            self.tstat_tcp_complete_file,           # Tstat file (input file)
                self.streambot_trace_file,          # Streambot file (input file)
                    self.estat_tcp_complete_file)   # Estat file (output file)

        # Generate the frame and the file trace for UDP (output file)
        self.estat_udp_complete_file = self.wireshark_trace_file.replace(WIRESHARK_EXT, ESTAT_UDP_EXT)
        self.estat_udp_complete_file = self.estat_udp_complete_file.replace(WIRESHARK_PFX, ESTAT_UDP_PFX)

        # # Generate the frame associated to the UDP log complete
        # self.estat_tcp_complete_frame = etstat_tcp_complete(
        #     self.tstat_tcp_complete_file,           # Tstat file (input file)
        #         self.streambot_trace_file,          # Streambot file (input file)
        #             self.estat_tcp_complete_file)   # Estat file (output file)

        # Clean all Tstat outputs
        logs = [os.path.join(tstat_out_dir, f) for f in os.listdir(tstat_out_dir)]
        for log in logs:
            os.remove(log)
        os.removedirs(tstat_out_dir)


    def filter_views(self, channels):
        
        # By combining an oracle (something that tells when something happens)
        # and the Estat trace, we can filter TCP and (maybe UDP) flows during
        # a multimedia stream

        # Remove anything from Streambot frame that is not a channel log
        filtered_bot = self.streambot_trace_frame[self.streambot_trace_frame["EVENT"].str.contains("|".join(channels))]

        # Remove anything from Estat frame (TCP) in which the token is not available
        filtered_tcp = self.estat_tcp_complete_frame[self.estat_tcp_complete_frame["TOKEN"] != "NONE"]

        # Generate a list with all timestamps, the ones at which a view is started
        # and stopped.
        points = filtered_bot["FROM_ORIGIN_MS"].tolist()

        # Loop over points, by coupling ts (time start) and te (time end)
        for ts, te in zip(points[::2], points[1::2]):
            
            # Isolate the window in which each flows has been started
            # after ts and before te
            window = filtered_tcp[(filtered_tcp["TS_FP"] >= ts) & (filtered_tcp["TS_FP"] <= te)]

            # Add to views list, the previous one (if not empty)
            if len(window) > 0:

                # Generate an object with some highlights
                view = {
                    "started":    window["DT_FP"].min(),        # Save the timestamp of flows that has started as first        
                    "finished":   window["DT_FP"].max(),        # Save the timestamp of flows that has finished as last
                    "first_row":  window["DT_FP"].idxmin(),     # Save the index of flow that has started as first
                    "last_row":   window["DT_FP"].idxmax(),     # Save the index of flow that has finished as last
                    "window":     window,                       # Save the dataframe
                    "tokens":     window["TOKEN"].tolist()      # Save the list of tokens associated to all flows
                }

                # Add this view to the list of views
                self.views.append(view)



def skygo_tokenizer(record):
    
    token = ""
    proto = "PROTO"

    # Determine the cname based on the protocol
    if proto in record:
        if record[proto] == "TLS":
            if "CN_CL" in record and record["CN_CL"] != "-":
                token = record["CN_CL"]
        elif record[proto] == "HTTP":
            if "HT_HN" in record and record["HT_HN"] != "-":
                token = record["HT_HN"]

    # If cname is still empty, check CN_DQ
    if token == "":
        if "CN_DQ" in record and record["CN_DQ"] != "-":
            token = record["CN_DQ"]

    # If cname is still empty, set to "NONE"
    if token == "":
        token = "NONE"

    # Replace hyphens with dots
    token = token.replace("-", ".")
    
    # Split the domain into parts
    domains = token.split(".")

    # Check if the domain has at least three parts
    if len(domains) >= 3:
        # Join the third last and second last elements, ignoring the TLD
        token = ".".join(domains[-3:-1])
    else:
        # If the domain has fewer than three parts, join all parts
        token = ".".join(domains)

    # Replace numbers with #
    token = re.sub(r"\d+", "#", token)

    return token


def generate_proto(record):

    name = record["PROTO"]
    name = PROTOCOLS[name]

    return "NONE" if name == None else name


def etstat_tcp_complete(tstat_tcp_complete_file, streambot_trace_file, estat_tcp_complete_file):

    # Generate a frame from Streambot trace
    bot_frame : pandas.DataFrame = pandas.read_csv(streambot_trace_file, delimiter=BOT_DEL)

    # Generate a frame from Estat TCP trace
    tcp_frame : pandas.DataFrame = pandas.read_csv(tstat_tcp_complete_file, delimiter=TST_DEL)

    # Generate a frame in which just few columns are used,
    # so you select just a slice of the original frame columns
    values  = list(TSTAT_COLUMNS.values())
    columns = list(TSTAT_COLUMNS.keys())

    tcp_frame = tcp_frame.iloc[:, values]
    tcp_frame.columns = columns

    # Make the origin in the Streambot frame the origin for all flows
    # in the TCP summary frame
    origin = bot_frame.loc[0, "UNIX_TS"]
    tcp_frame["TS_FP"] -= float(origin)
    tcp_frame["TS_LP"] -= float(origin)

    # Generate date format in Estat dataframe
    tcp_frame["DT_FP"] = pandas.to_datetime(tcp_frame["TS_FP"], unit="ms", origin="unix")
    tcp_frame["TS_LP"] = pandas.to_datetime(tcp_frame["TS_LP"], unit="ms", origin="unix")

    # Generate a human readable protocol value
    tcp_frame["PROTO"] = tcp_frame.apply(generate_proto, axis=1)

    # Generate the token
    tcp_frame["TOKEN"] = tcp_frame.apply(skygo_tokenizer, axis=1)

    # Sort Estat dataframe by date of first packet
    tcp_frame.sort_values(by="TS_FP", inplace=True)
    tcp_frame.reset_index(drop=True, inplace=True)
    tcp_frame.index += 1

    # Write the result on disk
    tcp_frame.to_csv(estat_tcp_complete_file, sep=TST_DEL, index=False, header=True)

    # Return the frame
    return tcp_frame, bot_frame


def compute_profile(experiments: list[Experiment], output: str):

    # Extract all views from the experiments
    views = [view for experiment in experiments for view in experiment.views]

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


def fetch_traces(root: str):

    wireshark_ext = ".pcap"
    streambot_ext = ".csv"

    wireshark_pfx = "wireshark_trace"
    streambot_pfx = "streambot_trace"

    files: list[str] = [os.path.join(root, f) for f in os.listdir(root)]

    # Get all Wireshark traces
    wireshark_traces_path: list[str] = [f for f in files 
        if os.path.basename(f).endswith(wireshark_ext) and os.path.basename(f).startswith(wireshark_pfx)
    ]

    # Get all Streambot traces
    streambot_traces_path: list[str] = [f for f in files
        if os.path.basename(f).endswith(streambot_ext) and os.path.basename(f).startswith(streambot_pfx)
    ]

    # Return the result
    return zip(sorted(wireshark_traces_path), sorted(streambot_traces_path))


def process_experiments(platform: str, channels: list[str]):

    # Define a list of Samples
    experiments : list[Experiment] = []

    # If a platform is specified, use "supervised" as database
    if platform:
        root = os.path.join(os.getcwd(), "supervised", platform)
    else:
        root = os.path.join(os.getcwd(), "unsupervised")

    files = fetch_traces(root)
    
    print(f"Processing experiments for platform: {platform}")

    # Generate SupervisedSample objects
    for wireshark_trace_file, streambot_trace_file in files:
        experiments.append(Experiment(wireshark_trace_file, streambot_trace_file))

    # Compile and process all experiments
    for experiment in experiments:
        experiment.tstat_wireshark_trace()
        experiment.filter_views(channels)

    print(f"Finished compiling and processing experiments for {platform}")
    
    # If a platform is not specified, return the list of experiments
    if platform is None:
        return experiments

    # If a platform is specified, save each experiment on disk
    save_experiments_on_disk(experiments, platform)

    # Generate the profile for that platform
    define_platform_profile(experiments, platform)


def save_experiments_on_disk(experiments: list[Experiment], platform: str):

    numb = 0
    root = os.path.join(os.getcwd(), f"events_{platform}")

    # If the output directory does not exist, create it. If it already exists,
    # cleanup all files in the directory

    if os.path.exists(root):

        # Remove all files in the output directory
        for f in os.listdir(root):
            os.remove(os.path.join(root, f))

    else:
        os.mkdir(root)

    print(f"Saving samples for platform: {platform}")

    for experiment in experiments:

        # Get the registered views for this experiment
        for view in experiment.views:
            
            path = os.path.join(root, f"sample-{numb}.dat")
            with open(path, "w") as f:

                # Loop over all tokens registered in the view
                for token in view["tokens"]:
                    f.write(f"{token}\n")
            numb += 1

    print(f"Finished saving samples for {platform}")


def define_platform_profile(experiments: list[Experiment], platform: str):

    profile = os.path.join(os.getcwd(), f"{platform}-profile.dat")
    if os.path.exists(profile):
        os.remove(profile)

    print(f"Computing {platform} profile...")

    compute_profile(experiments, profile)
    
    print(f"Finished computing {platform} profile. Profile saved to {profile}")