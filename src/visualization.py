import matplotlib.pyplot as plt
import pandas as pd
import os

class Visualizer:
    def __init__(self):
        pass

    def plot_anomalies(self, df, predictions, scores, output_path="data/anomaly_plot.png"):
        """
        Generates a scatter plot of anomaly scores over time.
        Highlights anomalies in red and normal events in blue.
        """
        if df.empty or 'Timestamp' not in df.columns:
            print("[-] Cannot plot: Empty DataFrame or missing Timestamp.")
            return

        plt.figure(figsize=(12, 6))

        # Assign colors based on predictions (-1 for anomaly -> red, 1 for normal -> blue)
        colors = ['red' if p == -1 else 'blue' for p in predictions]
        
        # Plot Scatter
        plt.scatter(df['Timestamp'], scores, c=colors, alpha=0.6, edgecolors='w', s=50)

        # Labels and Title
        plt.title('AetherHunt: Sysmon Anomaly Detection via Isolation Forest')
        plt.xlabel('Timestamp')
        plt.ylabel('Anomaly Score (Lower = More Anomalous)')
        
        # Legend (Custom handling since color mapping is list-based)
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Normal (Inlier)'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Anomaly (Outlier)')
        ]
        plt.legend(handles=legend_elements, loc='upper right')

        plt.grid(True, linestyle='--', alpha=0.5)
        plt.tight_layout()
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save and show
        plt.savefig(output_path)
        print(f"[+] Plot saved to {output_path}")
        plt.show()
