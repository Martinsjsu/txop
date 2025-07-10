import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load CSV data
df = pd.read_csv('txop_results.csv')

# Filter out the not-ended-properly records
df = df[df['Ended Properly'] == 'yes']

# Find most frequent stations
most_frequent_station_1 = df['From'].value_counts().idxmax()
print("Most frequent station in From is", most_frequent_station_1)

most_frequent_station_2 = df['To'].value_counts().idxmax()
print("Most frequent station in To is", most_frequent_station_2)

# === Plot ECDF for 'From' station ===
filtered_station = df[df['From'] == most_frequent_station_1]
txop_values = filtered_station['duration']

# Compute statistics
total_duration = txop_values.sum()
mean_duration = txop_values.mean()
median_duration = txop_values.median()
count = len(txop_values)

print("Max duration in 'From':", txop_values.max())
print("Total duration:", total_duration)
print("Average duration:", mean_duration)
print("Median duration:", median_duration)
print("Number of records:", count)

# Plot
sns.ecdfplot(txop_values)

# Vertical lines
plt.axvline(mean_duration, color='r', linestyle='--')
plt.axvline(median_duration, color='g', linestyle='--')

# Add annotations near the vertical lines
plt.annotate(f'Mean: {mean_duration:.2f}', xy=(mean_duration, 0.95), xytext=(-10, 0),
             textcoords='offset points', color='r', rotation=90, va='top', fontsize=9)

plt.annotate(f'Median: {median_duration:.2f}', xy=(median_duration, 0.95), xytext=(10, 0),
             textcoords='offset points', color='g', rotation=90, va='top', fontsize=9)

# Count annotation near the top-left corner of the plot (optional)
plt.annotate(f'Number of TXOP is {count}', xy=(0.01, 0.99), xycoords='axes fraction',
             ha='left', va='top', fontsize=10, bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='gray'))

# Labels and grid
plt.xlabel('TXOP Duration')
plt.ylabel('ECDF')
plt.title(f"ECDF for 'From' = {most_frequent_station_1}")
plt.grid(True)
plt.show()

# === Plot ECDF for 'To' station ===
filtered_station = df[df['To'] == most_frequent_station_2]
txop_values = filtered_station['duration']

# Compute statistics
total_duration = txop_values.sum()
mean_duration = txop_values.mean()
median_duration = txop_values.median()
count = len(txop_values)

print("Max duration in 'To':", txop_values.max())
print("Total duration:", total_duration)
print("Average duration:", mean_duration)
print("Median duration:", median_duration)
print("Number of records:", count)

# Plot
sns.ecdfplot(txop_values)

# Vertical lines
plt.axvline(mean_duration, color='r', linestyle='--')
plt.axvline(median_duration, color='g', linestyle='--')

# Add annotations near the vertical lines
plt.annotate(f'Mean: {mean_duration:.2f}', xy=(mean_duration, 0.95), xytext=(-10, 0),
             textcoords='offset points', color='r', rotation=90, va='top', fontsize=9)

plt.annotate(f'Median: {median_duration:.2f}', xy=(median_duration, 0.95), xytext=(10, 0),
             textcoords='offset points', color='g', rotation=90, va='top', fontsize=9)

# Count annotation near the top-left corner of the plot (optional)
plt.annotate(f'Number of TXOP is {count}', xy=(0.01, 0.99), xycoords='axes fraction',
             ha='left', va='top', fontsize=10, bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='gray'))

# Labels and grid
plt.xlabel('TXOP Duration')
plt.ylabel('ECDF')
plt.title(f"ECDF for 'To' = {most_frequent_station_2}")
plt.grid(True)
plt.show()
