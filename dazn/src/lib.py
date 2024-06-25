import os
import re
import shutil
import pandas
from collections import OrderedDict

# Estat extensions and prefixes
ESTAT_EXT = ".csv"
ESTAT_PFX = "tcp_log"
# Tstat extensions and prefixes
TSTAT_EXT = ".pcap.out"
TSTAT_PFX = "traces"
# Wireshark extensions and prefixes
SHARK_PFX = "traces"
SHARK_EXT = ".pcap"
# Streambot extensions and prefixes
PYBOT_EXT = ".csv"
PYBOT_PFX = "events"

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
PYBOT_DEL = '\t'
TSTAT_DEL = ' '

# Binaries
TSTAT_PATH = "/usr/local/bin/tstat"


def remove_files(tstat_files, estat_files):
    for file in tstat_files + estat_files:
        if os.path.isfile(file):
            os.remove(file)
        if os.path.isdir(file):
            shutil.rmtree(file)


def fetch_files(dir, pfx, ext):
    files = []
    for f in os.listdir(dir):
        if f.endswith(ext) and f.startswith(pfx):
            files.append(os.path.join(dir, f))
    return files


def load_data_files(dir):

    if not os.path.exists(dir) or not os.listdir(dir):
        print(f"Error: {dir} may not exist or be empty.")
        return None, None

    tstat_files = fetch_files(dir, TSTAT_PFX, TSTAT_EXT)
    estat_files = fetch_files(dir, ESTAT_PFX, ESTAT_EXT)
    remove_files(tstat_files, estat_files)

    shark_files = fetch_files(dir, SHARK_PFX, SHARK_EXT)
    pybot_files = fetch_files(dir, PYBOT_PFX, PYBOT_EXT)

    shark_files = sorted(shark_files)
    pybot_files = sorted(pybot_files)

    return shark_files, pybot_files


def load_data_frames(dir):

    if not os.path.exists(dir) or not os.listdir(dir):
        print(f"Error: {dir} may not exist or be empty.")
        return None, None

    estat_files = fetch_files(dir, ESTAT_PFX, ESTAT_EXT)
    pybot_files = fetch_files(dir, PYBOT_PFX, PYBOT_EXT)

    estat_files = sorted(estat_files)
    pybot_files = sorted(pybot_files)

    estat_frames = [pandas.read_csv(f, delimiter=TSTAT_DEL) for f in estat_files]
    pybot_frames = [pandas.read_csv(f, delimiter=PYBOT_DEL) for f in pybot_files]

    return estat_frames, pybot_frames


def skygo_tokenizer(record):
    cname = ""
    proto = "PROTO"

    if proto in record:
        if record[proto] == "TLS":
            if "CN_CL" in record and record["CN_CL"] != "-":
                cname = record["CN_CL"]
        elif record[proto] == "HTTP":
            if "HT_HN" in record and record["HT_HN"] != "-":
                cname = record["HT_HN"]

    if cname == "":
        if "CN_DQ" in record and record["CN_DQ"] != "-":
            cname = record["CN_DQ"]

    if cname == "":
        cname = "NONE"

    domains = cname.split(".")
    cname = ".".join(domains[-3:])
    cname = re.sub(r"\d+", "#", cname)

    return cname


def dazn_tokenizer(record):
    cname = ""
    proto = "PROTO"

    if proto in record:
        if record[proto] == "TLS":
            if "CN_CL" in record and record["CN_CL"] != "-":
                cname = record["CN_CL"]
        elif record[proto] == "HTTP":
            if "HT_HN" in record and record["HT_HN"] != "-":
                cname = record["HT_HN"]

    if cname == "":
        if "CN_DQ" in record and record["CN_DQ"] != "-":
            cname = record["CN_DQ"]

    if cname == "":
        cname = "NONE"

    cname = cname.replace("-", ".")
    domains = cname.split(".")
    cname = ".".join(domains[-3:])
    cname = re.sub(r"\d+", "#", cname)
    return cname


def estat(tstat_file, pybot_file, estat_file, provider):

    def generate_proto(record):
        name = record["PROTO"]
        name = PROTOCOLS[name]
        if name == None:
            return "NONE"
        return name

    # Generate Estat dataframe
    estat_frame = pandas.read_csv(tstat_file, delimiter=TSTAT_DEL)
    vals = list(TSTAT_COLUMNS.values())
    keys = list(TSTAT_COLUMNS.keys())
    estat_frame = estat_frame.iloc[:, vals]
    estat_frame.columns = keys

    # Generate PyBot dataframe
    pybot_frame = pandas.read_csv(pybot_file, delimiter=PYBOT_DEL)

    # Align Estat timestamps to PyBot origin
    origin = pybot_frame.loc[0, "UNIX_TS"]
    estat_frame["TS_FP"] -= float(origin)
    estat_frame["TS_LP"] -= float(origin)

    # Generate date format in Estat dataframe
    estat_frame["DT_FP"] = pandas.to_datetime(
        estat_frame["TS_FP"], unit="ms", origin="unix")
    estat_frame["TS_LP"] = pandas.to_datetime(
        estat_frame["TS_LP"], unit="ms", origin="unix")

    # Generate Canonical Name in Estat dataframe
    if provider == "skygo":
        estat_frame["CNAME"] = estat_frame.apply(skygo_tokenizer, axis=1)
    if provider == "dazn":
        estat_frame["CNAME"] = estat_frame.apply(dazn_tokenizer, axis=1)

    estat_frame["PROTO"] = estat_frame.apply(generate_proto, axis=1)
    # Generate description in Estat dataframe
    # estat_frame["BRIEF"] = estat_frame.apply(generate_brief, axis=1)

    # Sort Estat dataframe by date of first packet
    estat_frame.sort_values(by="TS_FP", inplace=True)
    estat_frame.reset_index(drop=True, inplace=True)
    estat_frame.index += 1

    # Write Estat dataframe to file
    estat_frame.to_csv(estat_file, sep=TSTAT_DEL, index=False, header=True)


def find_events(folders, channels):
    medias, traces = [], []

    # Load data as data frames
    for folder in folders:
        ms, ts = load_data_frames(folder)
        medias.extend(ms)
        traces.extend(ts)

    docs = []

    for media, trace in zip(medias, traces):

        # Remove all bot event that are not related to any multimedia start-stop
        trace = trace[trace["EVENT"].str.contains("|".join(channels))]
        # Remove all unrecognized flows
        media = media[media["CNAME"] != "NONE"]

        tims = trace["FROM_ORIGIN_MS"].tolist()
        for ts, te in zip(tims[::2], tims[1::2]):
            event = media[(media["TS_FP"] >= ts) & (media["TS_FP"] <= te)]
            if not event.empty:
                docs.append(event["CNAME"].tolist())

    for folder in folders:

        plt = folder.split("_")[1]
        dir = os.path.join(os.getcwd(), f"events_{plt}")

        # Remove all previous result
        if os.path.exists(dir):
            files = os.listdir(dir)
            files = [os.path.join(dir, file) for file in files]
            for f in files:
                os.remove(f)
            os.removedirs(dir)
        os.mkdir(dir)

        for i, doc in enumerate(docs):
            file_path = os.path.join(dir, f"doc-{i}.txt")
            with open(file_path, "w") as f:
                f.write("\n".join(doc) + "\n")


def determine_stream_token(folders, channels, out):
    medias, traces = [], []

    # Load data as data frames
    for folder in folders:
        ms, ts = load_data_frames(folder)
        medias.extend(ms)
        traces.extend(ts)

    stats = []

    for media, trace in zip(medias, traces):

        # Remove all bot event that are not related to any multimedia start-stop
        trace = trace[trace["EVENT"].str.contains("|".join(channels))]
        # Remove all unrecognized flows
        media = media[media["CNAME"] != "NONE"]

        tims = trace["FROM_ORIGIN_MS"].tolist()
        for ts, te in zip(tims[::2], tims[1::2]):
            event = media[(media["TS_FP"] >= ts) & (media["TS_FP"] <= te)]
            if not event.empty:
                down = event.groupby("CNAME")["DW_BY"].sum().to_dict()
                stats.append(max(down, key=down.get))

    cnt = {stat: stats.count(stat) for stat in stats}
    tot = sum(cnt.values())

    with open(out, "w") as f:
        for key, value in cnt.items():
            probability = value / tot
            f.write(f"{key}\t{probability:.1f}\n")


def process_folders(folders, provider):
    sharks, traces = [], []

    # Load data from disk
    for folder in folders:
        shks, evts = load_data_files(folder)
        sharks.extend(shks)
        traces.extend(evts)

    # Generate Tstat output files
    for i, shark in enumerate(sharks):
        os.system(f"{TSTAT_PATH} {shark} > /dev/null")

    # Clean each Tstat output
    for i, shark in enumerate(sharks):
        root = shark.replace(SHARK_EXT, TSTAT_EXT)
        dirs = [os.path.join(root, dir) for dir in os.listdir(root)]

        for dir in dirs:
            logs = [os.path.join(dir, f) for f in os.listdir(dir)]
            for log in logs:
                new = os.path.join(root, os.path.basename(log))
                os.rename(log, new)
            os.rmdir(dir)
            break

    file = "log_tcp_complete"
    # Run Estat on each TCP log complete
    for i, shark in enumerate(sharks):
        root = shark.replace(SHARK_EXT, TSTAT_EXT)
        tstat_log = os.path.join(root, file)
        estat_log = shark.replace(SHARK_PFX, ESTAT_PFX).replace(SHARK_EXT, ESTAT_EXT)
        estat(tstat_log, traces[i], estat_log, provider)

    # Clean Tstat output
    for shark in sharks:
        root = shark.replace(SHARK_EXT, TSTAT_EXT)
        logs = [os.path.join(root, f) for f in os.listdir(root)]
        for log in logs:
            os.remove(log)
        os.removedirs(root)


def find_cas(folders, cas_file):
    docs = []

    for folder in folders:
        files = [os.path.join(folder, f) for f in os.listdir(folder)]

        for file in files:
            with open(file, "r") as f:
                doc = []
                for line in f:
                    doc.append(line.strip())
                doc = set(doc)
                docs.append(list(doc))

    cas = set(docs[0])
    for doc in docs[1:]:
        cas &= set(doc)

    with open(cas_file, "w") as f:
        for word in list(cas):
            f.write(f"{word}\n")

def find_fad(folders, cas_file, media_file, fad_file):
    docs  = []
    keys  = []
    media = []

    with open(cas_file, "r") as f:
        for line in f:
            name = line.strip().split("\t")[0]
            keys.append(name)

    with open(media_file, "r") as f:
        for line in f:
            name = line.strip().split("\t")[0]
            media.append(name)

    for folder in folders:
        files = [os.path.join(folder, f) for f in os.listdir(folder)]

        for file in files:
            with open(file, "r") as f:
                doc = []
                for line in f:
                    name = line.strip()
                    if name in keys:
                        doc.append(name)
                doc = OrderedDict.fromkeys(doc)
                docs.append(list(doc))


    docs = [[word for word in OrderedDict.fromkeys(doc)] for doc in docs]
    pivt = None
    if len(media) > 0:
        pivt = media[0]

    fad = {}
    for doc in docs:
        if pivt in doc:
            index = doc.index(pivt)
            if index > 0:
                prev = doc[index - 1]
                if prev in fad:
                    fad[prev] += 1
                else:
                    fad[prev] = 1

    with open(fad_file, "w") as f:
        tot = len(docs)
        for key, value in fad.items():
            prob = value / tot
            f.write(f"{key}\t{prob:.1f}\n")