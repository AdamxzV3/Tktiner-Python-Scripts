import os
import requests
import ipaddress
import tkinter as tk

def clear_console():
    if os.name == "nt":
        os.system("cls")  # For Windows
    else:
        os.system("clear")  # For Linux and macOS

def ip_lookup(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query,continentCode,countryCode,region,regionCode,asname,asType,asDomain,zipCode,elevation,usageType"
    response = requests.get(url)
    data = response.json()

    if data["status"] == "success":
        result = f"IP: {data['query']}\n"
        result += f"Continent: {data['continent']} ({data['continentCode']})\n"
        result += f"Country: {data['country']} ({data['countryCode']})\n"
        result += f"Region: {data['regionName']} ({data['region']})\n"
        result += f"City: {data['city']}\n"
        result += f"ZIP Code: {data.get('zip')}\n"  # Use .get() method to handle missing 'zip' field
        result += f"Latitude: {data['lat']}\n"
        result += f"Longitude: {data['lon']}\n"
        result += f"Timezone: {data['timezone']}\n"
        result += f"ISP: {data['isp']}\n"
        result += f"Organization: {data['org']}\n"
        result += f"AS: {data['as']} ({data['asname']})\n"
        result += f"Reverse DNS: {data['reverse']}\n"
        result += f"Mobile: {data['mobile']}\n"
        result += f"Proxy: {data['proxy']}\n"
        result += f"Hosting: {data['hosting']}"
    else:
        result = f"Error occurred: {data['message']}"

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, result)

def lookup_button_clicked():
    ip = ip_entry.get()
    if ip.lower() == "exit":
        root.quit()
    else:
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_type = ip_obj.version  # Get IP version (4 for IPv4, 6 for IPv6)
            ip_lookup(str(ip_obj))
        except ValueError:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Invalid IP address.")

    ip_entry.delete(0, tk.END)

root = tk.Tk()
root.title("IP Lookup")
root.geometry("400x500")
root.configure(bg="#f0f0f0")

# Header Frame
header_frame = tk.Frame(root, bg="#333333", pady=10)
header_frame.pack(fill=tk.X)

header_label = tk.Label(header_frame, text="IP Lookup", font=("Arial", 18), fg="white", bg="#333333")
header_label.pack()

# Content Frame
content_frame = tk.Frame(root, bg="#f0f0f0")
content_frame.pack(pady=20)

ip_label = tk.Label(content_frame, text="Enter the IP address (or 'exit' to quit):", font=("Arial", 12), bg="#f0f0f0")
ip_label.pack(pady=10)

ip_entry = tk.Entry(content_frame, width=30, font=("Arial", 12))
ip_entry.pack(pady=5)

lookup_button = tk.Button(content_frame, text="Lookup", font=("Arial", 12), command=lookup_button_clicked)
lookup_button.pack(pady=5)

result_text = tk.Text(content_frame, height=15, width=40, font=("Arial", 12))
result_text.pack(pady=10)

root.mainloop()
