import pandas as pd
import os

def contains_keyword(cluster, keywords, column='CNAME'):
    if not cluster:
        return False
    return pd.DataFrame(cluster)[column].str.contains('|'.join(keywords)).any()

def generate_clusters(frame):

    cas = []
    clusters = []
    cluster  = []

    delim_prob  = float('-inf')
    media_prob = float('-inf')
    delim = None
    media = None
    
    # Get the list of Constant Asked Servers
    file = os.path.join(os.getcwd(), "cas.dat")
    with open(file, "r") as f:
        for line in f:
            cas.append(line.strip())

    # Get the list of Frequent Asked Delimiters
    # and save the most probable delimiter
    file = os.path.join(os.getcwd(), "fad.dat")
    with open(file, "r") as f:
        for line in f:
            parts = line.split('\t')
            if len(parts) == 2:
                name = parts[0]
                prob = float(parts[1])
                if prob > delim_prob:
                    delim_prob = prob
                    delim  = name

    # Get the list of audio video server
    file = os.path.join(os.getcwd(), "media.dat")
    with open(file, "r") as f:
        for line in f:
            parts = line.split('\t')
            if len(parts) == 2:
                name = parts[0]
                prob = float(parts[1])
                if prob > media_prob:
                    media_prob = prob
                    media = name                

    # Remove all unwanted flows
    # Remove all unwanted flows
    frame = frame[frame["CNAME"] != "NONE"]
    frame = frame[frame["CNAME"].str.contains('|'.join(cas))]

    # Remove all unwanted flows from the dataframe
    frame = frame[frame["CNAME"] != "NONE"]
    frame = frame[frame["CNAME"].str.contains('|'.join(cas))]

    # Create clusters based on the delimiter
    for _, record in frame.iterrows():
        if record["CNAME"] == delim:  
            # Check if the current record's CNAME is the delimiter
            if contains_keyword(cluster, cas):
                # If the current cluster is not empty and contains CAS 
                # keywords, append it to clusters
                clusters.append(pd.DataFrame(cluster))
              # Start a new cluster with the current record
            cluster = [record.to_dict()]
        else:
            # Add the current record to the current cluster
            cluster.append(record.to_dict())

    # Append the last cluster if it contains CAS keywords
    if contains_keyword(cluster, cas):
        clusters.append(pd.DataFrame(cluster))

    # Filter clusters to only include those that contain the media server
    result = [cluster 
        for cluster in clusters if cluster['CNAME'].str.contains(media).any()]

    return result

if __name__ == "__main__":

    path = os.path.join(os.getcwd(), "supervised", "stream_destop")
    file = os.path.join(path, "tcp_log-0.csv")

    print(file)
    frame = pd.read_csv(file, delimiter=' ')

    print(path)

    clusters = generate_clusters(frame)
    print(f"Find {len(clusters)} clusters")
    for i, cluster in enumerate(clusters, start=1):
        print(f"Cluster {i}:")
        print(cluster)
        print()