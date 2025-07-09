import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load Excel data
df = pd.read_csv('txop_results.csv')  # Replace with your filename
target_station = 'd0:65:78:3c:f4:e2'
filtered_station = df[df['From'] == target_station]
txop_values = filtered_station['duration']  # Replace 'TXOP' with your column name
print(max(txop_values))
sns.ecdfplot(txop_values)
plt.xlabel('TXOP')
plt.ylabel('ECDF')
plt.grid(True)
plt.show()
# Plot ECDF
# sns.ecdfplot(txop_values)
# plt.xlabel('TXOP')
# plt.ylabel('ECDF')
# plt.title('ECDF of TXOP values')
# plt.grid(True)
# plt.show()