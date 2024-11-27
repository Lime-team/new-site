# import ngrok python sdk
import ngrok
import time

# Establish connectivity
listener = ngrok.forward(80, authtoken_from_env=False, authtoken="2hkFup8GGd6hWdmFa3atwqTD3Iq_3sfKhg3Xaxh2FN9gtUNqx")

# Output ngrok url to console
print(f"Ingress established at {listener.url()}")

# Keep the listener alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Closing listener")