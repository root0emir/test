import os
import sys
import time
from colorama import init, Fore, Style

init(autoreset=True)


import os
from colorama import init, Fore, Style

# colorama
init(autoreset=True)

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')  # ekranı temizle

    # Renkli ve şık ASCII banner
    print(Fore.RED + Style.BRIGHT + """
   

      
        __     _                      _      ___                _             _   _
  /\ \ \___| |___      _____  _ __| | __ / _ \___ _ __   ___| |_ _ __ __ _| |_(_) ___  _ __
 /  \/ / _ \ __\ \ /\ / / _ \| '__| |/ // /_)/ _ \ '_ \ / _ \ __| '__/ _` | __| |/ _ \| '_ \
/ /\  /  __/ |_ \ V  V / (_) | |  |   </ ___/  __/ | | |  __/ |_| | | (_| | |_| | (_) | | | |
\_\ \/ \___|\__| \_/\_/ \___/|_|  |_|\_\/    \___|_| |_|\___|\__|_|  \__,_|\__|_|\___/|_| |_|

 _____          _   _            _____            _ _    _ _
/__   \___  ___| |_(_)_ __   __ /__   \___   ___ | | | _(_) |_
  / /\/ _ \/ __| __| | '_ \ / _` |/ /\/ _ \ / _ \| | |/ / | __|
 / / |  __/\__ \ |_| | | | | (_| / / | (_) | (_) | |   <| | |_
 \/   \___||___/\__|_|_| |_|\__, \/   \___/ \___/|_|_|\_\_|\__|
                            |___/    


                                                                                                                        
                                                                                                          .:=+++        
                                                                                                     .:=*%%%%#=:        
                                                                                                 .=+#%%%%#+-.           
                                                                                              :=#%%%%%%*:               
                                                                                           .=#%@%%%%*-.                 
                                                                                         :*%%%%%%#=.           .......  
                                                                                      :+#%%%%%#+-   .:-=+**###%%%%%%%%#-
                                                                          -+**:   :=*#%%%%%%*-..:=*#%%%%%%%%%%%%%%#*+-: 
                                                                       :+#%%%=.:+#%@@%%%%%+=+*%%%%%%%%%%%%%#*+=-:       
                                                                     :+%%%@@*+#%@@@@@@@%%%%%%%%%%%%%%#*+=:.             
                                                                   .+%%@@@@@@@@@@@@@@@@@@@%%%%%#*+==------:::..         
        .                                                         .#%%@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%#*+-.   
 ..    -#+    -*-                                                :#%%@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%##***######%%%%#*.
=%#:   +%#-  -##=   -*=                                         :#%%@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%#*+==-:.  ..::::.
-%%#:  +%#*..*##= .*##=                                        -%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%#=.      
 =%%#: -%%#-.#%#=.*###:  :+-                                  :#%%@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%#####%%%#=.   
  +%%#=.#%%*:#%#**####:-*##=                                 :#%%@@@@@@@@@@@@@@@@@%%%@@@%%%%%%%%%%%%%%%%%%%%%*=-=*%%%*: 
   -%%%=:#%%++%##%###**###*.                                -#%%@@@@@@@@@@@@@@@@@%%%@@@%%%%%%%%%%%%%%%%%%%%%%%%%*-..--: 
    .+%%*=#%%#%%#%%##%####:.:=-.                           =%%@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%+=*#%%%%%%%=.   
      :#%%%%%%%%%%%%%%#%#=+##%#:                         .*%%@@@@@@@@@@@@@@@@@@%%%%%%@%%%%%%%%%%%%%%%%%%*  .-+*#%%%%#=  
   .**=-+%%%%%%%%%%%%%%%##%%%*.....                    :+%%%@@@@@@@@@@@@@@@@@%@%%%%%%%%%%%%%%%%%%%+-===-        .::--:  
    .-*%#*#%%%%%%%%%%%%%%%%%%##%%%%#*:               -*%%%%@@@@@@@@@@@@@@@@@@@@%%@@@%%%%%%%%%%%%%%%=                    
       .=#%@@%%%%%%%%%%%%%%%%%%%%#*+=-::.         .-#%%%@@@@@@@@@@@@@@@@@@@@@%%@@@@@%%%%%%%%%%#***=.                    
           :+#@@%%%%%%%%%%#*+=-:::+#####*+=---:.-+#%%%@@@@@@@@@@@@@@@@@@@@@@@@%@%%%%%%%%%%%%%%%*:                       
              .=#%%%#+=:.         +############%%%%%@@@@@@@@@@@@@@@@@@@@@@@@%%@@@@%%%%%%%%%%%%%%+                       
            ....                  .+#%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%*--:.                        
          .:..   ......           =#%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@%%%%%%%%%%%+                           
        :::....-++=:...          =%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@%%%%%%%%%%+++.                           
       :-:::=*##*=::::............*%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%#.                             
     .----+%%%##=-::::::::::::::::*%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%#+.                             
     :=+*###%%#+-----====-----=--*%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%#=                                
   .---++++++++++**********++++++%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%#+*%%%#:                                  
  :-=+==++**#**++++++==++*****+#%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%=:--.                                   
 :--=++*#*+=:..          .-+*##%%%%%%%%%%%%%%%%%%%%@@@@%%%@@@@@%%%%%%%%%%%%%%%%#*-                                      
 .==++*+:                   :###%%%%%%%%%%%%%%%%%%%%%@@%%%%####*%%%%%%%%%%%%%%+                                         
  .=+*=                       =##%%%%%%%%%%%%%%%%%%%%%%%%%%###*=.:=*#%%%%#*=:                                           
    :=-                        -*##%%%@@@@%%%%%%%%%%%%%%%%%####*=.                                                      
                                .=##%%%@@@@@%%%%%%%%%%%%%%%%%###*+:                                                     
                                  :+#%%%%@@@@%%%%%%%%%%%%%%%%%%%##*-                                                    
                                    :*%%%%%@@@@%%%%%%%%%%%%%%%%%%##*-                                                   
                                      :*%%@%%%%%%%%%%%%%%%%%%%%%%%%#*=.                                                 
                                    .+%@@@@@%%%%%%%%%%%%%%%%%%%%%%%%##*:                                                
                                  :+%@@@@@@@@%%%%%%####%%%%%%%%@@@%%%##*-                                               
                               .-*%%@@@@@@@@@%#########%%%%%%%@@@@@%%%%##+:                                             
                 ..          :*%%%%%%@@@@@@%%##########%%%%%%@@@@@@@%%%%##*=.                                           
             .-=++++=:    :+#%%%%%%%%@@@@@%%##########%%%%%%%@@@@@@@@%%%%%*=--:.                                        
             -++*##***++++#%%%%%%%%%@@@@@%%###########%%%%%-.+%@@@@@%%%%%%#*++=--:.                                     
            :++*+..:-=+***+++=*%%%%%@@@%%%###########%%%%%=   -#%%%%%%%%%%####**+=--:..                                 
           .++*#%+.  -**.      :+#%@@@%%############%%%%%=     -#%%%%%%%%%#######**+=-::.                               
           =#*++%#:=+*#=   .-==-. .=#%##############%%%%#.     :*###%%%%%%###########*+=-:..                            
          -##- .*%#%#*-  .==++***=-:-*###########%%%%%%%=      -**###%#################**+=:....                        
          .*+   .-++.  .=+++-::+**+++**+=*###%##%%%%%%%%-      -**#########################*+=-::...                    
           .-.        :+**=  :==++++=:    .-*#%#%%%%%%%*:      -*#############################*++=-::...                
                     -#*=:   +++***-          -*%%%%%%-        .**##########################**###**++=--:               
                    .#*.    =#####-              :+**#-         -*##########################**########*+:               
                    .#:  .-+%#*=-.                   ..          .-**+::+*##############################*-.             
                     .     -%-                                            .-+***###=+*#######*-+*####*+***+             
                            -                                                   .:-.  .:--:-=-   :-+*+                  

        
    """)
    
    print(Fore.CYAN + Style.BRIGHT + "-------------------------------------------")
    print(Fore.GREEN + Style.BRIGHT + " Network Penetration Testing Toolkit ")
    print(Fore.CYAN + Style.BRIGHT + "-------------------------------------------")
    print(Fore.YELLOW + "A tool for network penetration testing.")
    print(Fore.YELLOW + "Created by: ?")
    print(Fore.YELLOW + "Version: 1.0")
    print(Fore.CYAN + Style.BRIGHT + "\n[Press any key to continue...]")

if __name__ == "__main__":
    print_banner()
    input()  # kullanici herhangi bir tuşa basana kadar bekle


import os
import sys
import time
from colorama import Fore, Style

def main_menu():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen
    print(Fore.GREEN + Style.BRIGHT + "Network Penetration Testing Kit")
    print(Fore.YELLOW + Style.BRIGHT + "1. ARP Spoofing")
    print(Fore.YELLOW + Style.BRIGHT + "2. Deauthentication Attack (Wi-Fi)")
    print(Fore.YELLOW + Style.BRIGHT + "3. Port Scanning (Nmap)")
    print(Fore.YELLOW + Style.BRIGHT + "4. DNS Spoofing")
    print(Fore.YELLOW + Style.BRIGHT + "5. Denial of Service (DoS)")
    print(Fore.YELLOW + Style.BRIGHT + "6. Distributed Denial of Service (DDoS)")
    print(Fore.YELLOW + Style.BRIGHT + "7. Man-in-the-Middle Attack")
    print(Fore.YELLOW + Style.BRIGHT + "8. Packet Sniffing")
    print(Fore.YELLOW + Style.BRIGHT + "9. Brute Force Attack")
    print(Fore.YELLOW + Style.BRIGHT + "10. Ping of Death")
    print(Fore.YELLOW + Style.BRIGHT + "11. Smurf Attack")
    print(Fore.YELLOW + Style.BRIGHT + "12. TCP SYN Flood")
    print(Fore.YELLOW + Style.BRIGHT + "13. UDP Flood")
    print(Fore.YELLOW + Style.BRIGHT + "14. DNS Amplification")
    print(Fore.YELLOW + Style.BRIGHT + "15. SSL Stripping Attack")
    print(Fore.YELLOW + Style.BRIGHT + "16. Session Hijacking")
    print(Fore.YELLOW + Style.BRIGHT + "17. Evil Twin (Wi-Fi Rogue AP)")
    print(Fore.YELLOW + Style.BRIGHT + "18. Wi-Fi Cracking (WPA/WPA2)")
    print(Fore.YELLOW + Style.BRIGHT + "19. ICMP Tunneling")
    print(Fore.YELLOW + Style.BRIGHT + "20. ARP Flood Attack")
    print(Fore.YELLOW + Style.BRIGHT + "21. Exit")
    print(Style.RESET_ALL)
    
    choice = input(Fore.CYAN + "Enter the number of the attack you want to perform: ")
    
    if choice == "1":
        os.system("python3 arp_spoof.py")  # Start ARP Spoofing
    elif choice == "2":
        os.system("python3 deauth_attack.py")  # Start Deauthentication Attack
    elif choice == "3":
        os.system("python3 nmap_scan.py")  # Start Nmap Scan
    elif choice == "4":
        os.system("python3 dns_spoof.py")  # Start DNS Spoofing
    elif choice == "5":
        os.system("python3 dos_attack.py")  # Start DoS attack
    elif choice == "6":
        os.system("python3 ddos_attack.py")  # Start DDoS attack
    elif choice == "7":
        os.system("python3 mitm_attack.py")  # Start MITM Attack
    elif choice == "8":
        os.system("python3 packet_sniff.py")  # Start Packet Sniffing
    elif choice == "9":
        os.system("python3 brute_force.py")  # Start Brute Force Attack
    elif choice == "10":
        os.system("python3 ping_of_death.py")  # Start Ping of Death
    elif choice == "11":
        os.system("python3 smurf_attack.py")  # Start Smurf Attack
    elif choice == "12":
        os.system("python3 syn_flood.py")  # Start TCP SYN Flood
    elif choice == "13":
        os.system("python3 udp_flood.py")  # Start UDP Flood
    elif choice == "14":
        os.system("python3 dns_amplification.py")  # Start DNS Amplification
    elif choice == "15":
        os.system("python3 ssl_stripping.py")  # Start SSL Stripping
    elif choice == "16":
        os.system("python3 session_hijacking.py")  # Start Session Hijacking
    elif choice == "17":
        os.system("python3 evil_twin.py")  # Start Evil Twin Attack
    elif choice == "18":
        os.system("python3 wifi_crack.py")  # Start Wi-Fi Cracking
    elif choice == "19":
        os.system("python3 icmp_tunneling.py")  # Start ICMP Tunneling
    elif choice == "20":
        os.system("python3 arp_flood.py")  # Start ARP Flood Attack
    elif choice == "21":
        sys.exit()  # Exit
    else:
        print(Fore.RED + "Invalid choice, please try again.")
        time.sleep(2)
        main_menu()

   

# Ana fonksiyon başlatma
if __name__ == "__main__":
    main_menu()
