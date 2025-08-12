#!/usr/bin/env python
from matplotlib import pyplot as plt
import numpy as np

rates = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 30]

with open("aes256_avrg.txt") as f:
    aes256 = [float(x) for x in f.read().strip().split(" ")]
    
with open("aes256_error.txt") as f:
    aes256_err = [float(x) for x in f.read().strip().split(" ")]
    
# Calcolo limiti superiori e inferiori per l'intervallo di confidenza
aes256_sup = [aes256[i] + aes256_err[i] for i in range(len(aes256))]
aes256_inf = [aes256[i] - aes256_err[i] for i in range(len(aes256))]

with open("aes128_avrg.txt") as f:
    aes128 = [float(x) for x in f.read().strip().split(" ")]
    
with open("aes128_error.txt") as f:
    aes128_err = [float(x) for x in f.read().strip().split(" ")]
    
aes128_sup = [aes128[i] + aes128_err[i] for i in range(len(aes128))]
aes128_inf = [aes128[i] - aes128_err[i] for i in range(len(aes128))]

with open("chacha20_avrg.txt") as f:
    chacha20 = [float(x) for x in f.read().strip().split(" ")]

with open("chacha20_error.txt") as f:
    chacha20_err = [float(x) for x in f.read().strip().split(" ")]
    
chacha20_sup = [chacha20[i] + chacha20_err[i] for i in range(len(chacha20))]
chacha20_inf = [chacha20[i] - chacha20_err[i] for i in range(len(chacha20))]

with open("no_proxy_avrg.txt") as f:
    no_proxy = [float(x) for x in f.read().strip().split(" ")]

with open("no_proxy_error.txt") as f:
    no_proxy_err = [float(x) for x in f.read().strip().split(" ")]
    
no_proxy_sup = [no_proxy[i] + no_proxy_err[i] for i in range(len(no_proxy))]
no_proxy_inf = [no_proxy[i] - no_proxy_err[i] for i in range(len(no_proxy))]

with open("proxy_noenc_avrg.txt") as f:
    proxy_noenc = [float(x) for x in f.read().strip().split(" ")]

with open("proxy_noenc_error.txt") as f:
    proxy_noenc_err = [float(x) for x in f.read().strip().split(" ")]
    
proxy_noenc_sup = [proxy_noenc[i] + proxy_noenc_err[i] for i in range(len(proxy_noenc))]
proxy_noenc_inf = [proxy_noenc[i] - proxy_noenc_err[i] for i in range(len(proxy_noenc))]
    
    

desired_y_ticks = [0.03, 0.3, 5, 10, 15, 20, 25]


plt.figure(figsize=(9,4.5), dpi=240)

# Plotting the graph
plt.plot(rates, aes256,'o-',markersize=5, label="AES-256-CBC", color='blue')
plt.fill_between(rates, aes256_inf, aes256_sup, color='blue', alpha=0.3)
plt.plot(rates, aes128,'o-', markersize=5,label="AES-128-CBC", color='orange')
plt.fill_between(rates, aes128_inf, aes128_sup, color='orange', alpha=0.3)
plt.plot(rates, chacha20,'o-',markersize=5,  label="ChaCha20", color='green')
plt.fill_between(rates, chacha20_inf, chacha20_sup, color='green', alpha=0.3)
plt.plot(rates, proxy_noenc,'o-', markersize=5, label="No encryption", color='red')
plt.fill_between(rates, proxy_noenc_inf, proxy_noenc_sup, color='red', alpha=0.3)
plt.plot(rates, no_proxy,'o-', markersize=5, label="No proxy", color='purple')
plt.fill_between(rates, no_proxy_inf, no_proxy_sup, color='purple', alpha=0.3)
plt.xlabel("Requests per second")
plt.ylabel("Average latency (sec)")

plt.yscale('log')

# Definire le posizioni delle etichette desiderate
yticks = [0.03, 0.04, 0.1 ,0.2, 5, 10, 15, 20, 30, 40]
xticks = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 30]
# Impostare le etichette personalizzate
plt.yticks(yticks, yticks)
plt.xticks(xticks, xticks)

# Aggiunge la legenda a destra in centro
plt.legend(loc="center right")

plt.grid(True, which="both", ls="-")


# Salvare il grafico
plt.savefig("Latency.png")