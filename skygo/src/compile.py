import os
from lib import Experiment, compute_profile
from lib import process_experiments

if __name__ == "__main__":
    channels = ["tg", "rai", "quattro", "cinque", "uno", "sport"]

    platforms = ["desktop", "mobile"]
    for platform in platforms:
        print("=" * 100)
        process_experiments(platform, channels)
