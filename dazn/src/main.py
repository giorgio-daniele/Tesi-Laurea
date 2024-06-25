import os
from collections import OrderedDict

from lib import process_folders
from lib import find_events
from lib import determine_stream_token
from lib import find_cas
from lib import find_fad

if __name__ == "__main__":

    provider = "dazn"
    channels = ["inter", "milan", "zona", "euro", "nfl"]

    # Generate Tstat files
    folders = ["stream_destop"]
    folders = [os.path.join(os.getcwd(), "supervised", folder) for folder in folders]
    process_folders(folders, provider)

    # Generate probabilty of multimedia token
    folders = ["stream_destop"]
    folders = [os.path.join(os.getcwd(), "supervised", folder) for folder in folders]
    media_file = os.path.join(os.getcwd(), "media.dat")
    determine_stream_token(folders, channels, media_file)

    # Find interesting events
    folders = ["stream_destop"]
    folders = [os.path.join(os.getcwd(), "supervised", folder) for folder in folders]
    find_events(folders, channels)

    # Determine Costant Asked Servers
    folders = ["events_destop"]
    folders = [os.path.join(os.getcwd(), folder) for folder in folders]
    cas_file = os.path.join(os.getcwd(), "cas.dat")
    find_cas(folders, cas_file)

    # Determine Frequent Asked Delimiter
    folders = ["events_destop"]
    folders = [os.path.join(os.getcwd(), folder) for folder in folders]
    fad_file = os.path.join(os.getcwd(), "fad.dat")
    find_fad(folders, cas_file, media_file, fad_file)
