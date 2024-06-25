import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import os

def plot_profile(file_name, title):
    tokens = []
    values = []

    # Leggi il file e popola le liste
    with open(file_name, 'r') as file:
        for line in file:
            probability, token = line.strip().split('\t')
            values.append(float(probability))
            tokens.append(token[:20])

    # Crea un DataFrame pandas
    data = pd.DataFrame({"Token": tokens, "Probability": values})

    # Configura il grafico con Seaborn
    plt.figure(figsize=(12, 8))
    ax = sns.barplot(x="Token", y="Probability", data=data, palette='viridis')

    # Ruota le etichette dell'asse x per renderle leggibili
    plt.xticks(rotation=90)

    # Aggiungi le etichette degli assi
    plt.xlabel("Token")
    plt.ylabel("Probability")

    # Aggiungi un titolo al grafico
    plt.title(title)

    # Aggiungi la griglia
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    ax.grid(axis='x', linestyle='--', alpha=0.7)

    # Migliora il layout
    plt.tight_layout()

    # Salva il grafico su file
    output_file = f"{title.lower().replace(' ', '-')}-profile.png"
    plt.savefig(output_file, dpi=300)

# Nome del file contenente i dati per il profilo desktop
desktop_file = os.path.join(os.getcwd(), "desktop-profile.dat")
plot_profile(desktop_file, "Desktop Tokens Probabilities")

# Nome del file contenente i dati per il profilo mobile
mobile_file = os.path.join(os.getcwd(), "mobile-profile.dat")
plot_profile(mobile_file, "Mobile Tokens Probabilities")
