import tkinter as tk
from tkinter import messagebox
import sqlite3
from pysnmp.hlapi import *


# Create SQLite database and table for credentials
conn = sqlite3.connect('snmp_app.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS credentials
             (username text, password text)''')
c.execute("INSERT INTO credentials VALUES (?, ?)", ("admin", "12345"))
c.execute('''CREATE TABLE IF NOT EXISTS set_values
             (ip text, oid text, value text)''')
conn.commit()


def snmp_get(ip, oid, community='public'):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )

    if errorIndication:
        result_text.set('SNMP Get request failed: %s' % errorIndication)
    elif errorStatus:
        result_text.set('SNMP Get request failed: %s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex) - 1] if errorIndex else '?'))
    else:
        value = varBinds[0][1].prettyPrint()
        result_text.set('OID: %s = %s' % (oid, value))


def snmp_set(ip, oid, value, community='public'):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        setCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid), value))
    )

    if errorIndication:
        result_text.set('SNMP Set request failed: %s' % errorIndication)
    elif errorStatus:
        result_text.set('SNMP Set request failed: %s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex) - 1] if errorIndex else '?'))
    else:
        result_text.set('SNMP Set request successful')

        # Insert the set values into the database
        c.execute("INSERT INTO set_values VALUES (?, ?, ?)", (ip, oid, value))
        conn.commit()


def perform_get():
    target_ip = ip_entry.get()
    target_oid = oid_entry.get()
    snmp_get(target_ip, target_oid)


def perform_set():
    target_ip = ip_entry.get()
    target_oid = oid_entry.get()
    new_value = value_entry.get()
    snmp_set(target_ip, target_oid, new_value)


def login():
    username = username_entry.get()
    password = password_entry.get()

    # Check if the provided credentials exist in the database
    c.execute("SELECT * FROM credentials WHERE username=? AND password=?", (username, password))
    result = c.fetchone()

    if result:
        messagebox.showinfo("Login Successful", "Logged in successfully!")
        login_window.destroy()
        show_main_window()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password!")


def show_main_window():
    global ip_entry, oid_entry, value_entry, result_text

    # Create the main SNMP application window
    window = tk.Tk()
    window.title('SNMP Application')
    window.geometry('700x600')

    canvas = tk.Canvas(window, bg="lightblue")
    canvas.pack(fill="both", expand=True)

    frame = tk.Frame(canvas, bg="lightblue")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    # Create IP entry field
    ip_label = tk.Label(frame, text='Target IP:')
    ip_label.pack(pady=5)
    ip_entry = tk.Entry(frame)
    ip_entry.pack(pady=5)

    # Create OID entry field
    oid_label = tk.Label(frame, text='OID:')
    oid_label.pack(pady=5)
    oid_entry = tk.Entry(frame)
    oid_entry.pack(pady=5)

    # Create Value entry field
    value_label = tk.Label(frame, text='Value (for Set):')
    value_label.pack(pady=5)
    value_entry = tk.Entry(frame)
    value_entry.pack(pady=5)

    # Create Get button
    get_button = tk.Button(frame, text='Get', command=perform_get)
    get_button.pack(pady=5)

    # Create Set button
    set_button = tk.Button(frame, text='Set', command=perform_set)
    set_button.pack(pady=5)

    # Create result label
    result_text = tk.StringVar()
    result_label = tk.Label(frame, textvariable=result_text)
    result_label.pack(pady=5)

    # Close the database connection when the GUI window is closed
    def on_closing():
        conn.close()
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", on_closing)
    window.mainloop()


# Create login window
login_window = tk.Tk()
login_window.title("Login")
login_window.geometry('700x600')

canvas = tk.Canvas(login_window, bg="sky blue")
canvas.pack(pady=50, padx=50, expand=True)

frame = tk.Frame(canvas, bg="sky blue")
frame.place(relx=0.5, rely=0.5, anchor="center")

# Create username label and entry field
username_label = tk.Label(frame, text="Username:")
username_label.pack(pady=5)
username_entry = tk.Entry(frame)
username_entry.pack(pady=5)

# Create password label and entry field
password_label = tk.Label(frame, text="Password:")
password_label.pack(pady=5)
password_entry = tk.Entry(frame, show="*")
password_entry.pack(pady=5)

# Create login button
login_button = tk.Button(frame, text="Login", command=login)
login_button.pack(pady=5)

# Close the database connection when the login window is closed
def on_login_closing():
    conn.close()
    login_window.destroy()

login_window.protocol("WM_DELETE_WINDOW", on_login_closing)
login_window.mainloop()
