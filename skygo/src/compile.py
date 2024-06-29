import os
from lib import Experiment, tokens_profile
from lib import process_experiments

def print_view(view):
    print(f"TIME START {view['time_s']} - TIME END {view['time_e']}\nINDEX START: {view['idex_s']} INDEX END: {view['idex_e']}")
    print()
    print("Tokens:")
    tokens = ", ".join(view['tokens'])
    print(tokens)
    print()
    print("Statistics:")
    print()
    # for key, group in view['lstats']:
    #     print(f"Grouped by {key}:")
    #print(view['lstats'])
    for key, value in view['lstats'].items():
        print(f"C_IP: {key[0]}\tS_IP: {key[1]}\tC_PORT: {key[2]}\tS_PORT: {key[3]}")
        print(value)
        print()


if __name__ == "__main__":
    channels = ["tg", "rai", "quattro", "cinque", "uno", "sport"]

    platforms = ["desktop", "mobile"]
    for platform in platforms:
        print("=" * 100)
        process_experiments(platform, channels)
    
    # experiments = process_experiments(None, channels)
    # for view in experiments[0].streaming_intervals_tcp:
    #     print_view(view)
    #     print("=" * 30)  # Separatore tra diverse view
