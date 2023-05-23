import subprocess
import tkinter as tk

def check_virtual_machine():
    result = subprocess.run('systeminfo', capture_output=True, text=True)
    output = result.stdout
    
    if 'Manufacturer:' in output and 'Microsoft' not in output:
        vm_label.config(text='Running in a virtual machine.', fg='green')
    else:
        vm_label.config(text='Not running in a virtual machine.', fg='red')

root = tk.Tk()
root.title("Virtual Machine Checker")
root.geometry("400x200")
root.configure(bg="#f0f0f0")

header_label = tk.Label(root, text="Virtual Machine Checker", font=("Arial", 18), bg="#333333", fg="white", pady=10)
header_label.pack(fill=tk.X)

start_button = tk.Button(root, text="Start", font=("Arial", 14), command=check_virtual_machine)
start_button.pack(pady=20)

vm_label = tk.Label(root, text="", font=("Arial", 14), bg="#f0f0f0")
vm_label.pack()

root.mainloop()
