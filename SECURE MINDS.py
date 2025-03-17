import tkinter as tk
from tkinter import messagebox
import random
import string
import re

# Function to start password puzzle section
def start_password_puzzle():
    home_frame.pack_forget()
    quiz_frame.pack_forget()
    info_guide_frame.pack_forget()
    puzzle_frame.pack(fill='both', expand=True)
    
    difficulty_levels = [
        ('Very Low', 4, string.ascii_lowercase + string.digits),
        ('Low', 6, string.ascii_letters + string.digits),
        ('Moderate', 8, string.ascii_letters + string.digits),
        ('High', 10, string.ascii_letters + string.digits + string.punctuation),
        ('Very High', 12, string.ascii_letters + string.digits + string.punctuation),
    ]
    
    current_level = 0

    def next_level():
        nonlocal current_level
        if current_level < len(difficulty_levels):
            difficulty, length, chars = difficulty_levels[current_level]
            current_level += 1

            level_label.config(text=f"Level {current_level}: {difficulty}")
            sample_chars.set("".join(random.choices(chars, k=length)))

    def check_password():
        password = password_entry.get()
        difficulty, length, chars = difficulty_levels[current_level - 1]

        if len(password) < length:
            result_label.config(text="Password too short, try again!", fg="red")
        elif not re.match(f'^[{re.escape(chars)}]+$', password):
            result_label.config(text="Password contains invalid characters, try again!", fg="red")
        else:
            result_label.config(text="Password accepted, advancing to next level!", fg="green")
            if current_level < len(difficulty_levels):
                next_level()
            else:
                result_label.config(text="Congratulations! You successfully completed the puzzle. Now you can create a safe, secure password for your accounts.", fg="blue")
                go_home_button.pack(pady=10)

    next_level()

    submit_button.config(command=check_password)

# Function to start quiz section
def start_quiz():
    home_frame.pack_forget()
    puzzle_frame.pack_forget()
    info_guide_frame.pack_forget()
    quiz_frame.pack(fill='both', expand=True)

    questions = [
        ("What is phishing?", "A) A type of fish", "B) A fraudulent attempt to obtain sensitive information", "C) A social media post", "D) None of the above", 2),
    ("What is a strong password?", "A) 123456", "B) password", "C) Pa$$w0rd!", "D) abcdefg", 3),
    ("What is malware?", "A) A type of fruit", "B) Malicious software", "C) An anti-virus program", "D) None of the above", 2),
    ("What is a firewall?", "A) A wall made of fire", "B) A type of computer virus", "C) Fire in the computer", "D) A security system to prevent unauthorized access", 4),
    ("What is encryption?", "A) A type of code language", "B) A network security protocol", "C) A method to make data unreadable without a key", "D) Writing a code", 3),
    ("What is spyware?", "A) Software used to monitor user activity", "B) A tool for cleaning spyware", "C) A virus protection software", "D) None of the above", 1),
    ("What is a Trojan horse?", "A) A type of horse", "B) A password manager", "C) A malicious program disguised as legitimate software", "D) A virus made to crash your system", 3),
    ("What is two-factor authentication?", "A) A password management tool", "B) A type of firewall", "C) An extra layer of security requiring two forms of identification", "D) Messaging between two people", 3),
    ("What is a botnet?", "A) A type of computer virus", "B) A software update tool", "C) A special ability of anti-virus software", "D) A network of computers infected with malware", 4),
    ("What is ransomware?", "A) Malware that demands payment to restore access to data", "B) A type of anti-virus software", "C) A phishing technique", "D) None of the above", 1),
    ("How to identify between a real email and an email sent for phishing?", "A) Both are same", "B) Check the grammar of the email", "C) Open the link to check", "D) Take a wild guess", 2),
    ("Cyber Se  curity provides security against what?", "A) Against Malware", "B) Against Malware", "C) Defends a device from threats", "D) All mentioned options", 4),
    ("Which of the below is a kind of cyber security?", "A) Cloud Security", "B) Application Security", "C) Antivirus", "D) All options mentioned above", 4),
    ("Which of the below does not constitute a cybercrime?", "A) Refusal of Service", "B) Man in the middle", "C) Phishing", "D) Advanced Encryption Standard", 4),
    ("Which of the below benefits of cyber security is not true?", "A) System getting slower", "B) Computer lagging and crashes", "C) Provide privacy to users", "D) Secures system against viruses", 1),
    ("Which of the below is a hacking technique in which cybercriminals create fictitious web pages or domains to deceive or obtain more traffic?", "A) Pharming", "B) Spamming", "C) Website-Duplication", "D) None of the above", 1),
    ("Which of the below is a popular method used by cyber attackers to gain the IP address of a target or victim user?", "A) Emails", "B) Websites", "C) IP tracer", "D) Web pages", 2),
    ("Which of the below does not qualify as a form of peer-to-peer cybercrime?", "A) Trojans are implanted into a targeted device.", "B) On the deep web, payment information is leaked", "C) Malware", "D) Phishing", 3),
    ("An act to injure, corrupt, or threaten a system or network is characterized as which of the below?", "A) Digital crime", "B) Threats", "C) System hijacking", "D) Cyber Attack", 4),
    ("Which of the below is an internet fraud in which a consumer is digitally persuaded to reveal personal data by cybercriminals?", "A) MiTM attack", "B) Phishing attack", "C) Website attack", "D) DoS attack", 2),
    ("Which of the below security encryption standards is the weakest?", "A) WPA3", "B) WPA2", "C) WPA", "D) WEP", 4),
    ("Which of the below measures can help reduce the risk of data leakage?", "A) Steganography", "B) Chorography", "C) Cryptography", "D) Authentication", 3),
    ("This is the concept for guiding information security policy within a corporation, firm, or organization. What exactly is “this” in this context?", "A) Confidentiality", "B) Non-repudiation", "C) CIA Triad", "D) Authenticity", 3),
    (" ___________ means the security of data from tampering by unidentified users", "A) Confidentiality", "B) Integrity", "C) Authentication", "D) Non-repudiation", 2),
    ("Which of the below implemented is not a good means of safeguarding privacy?", "A) Biometric verification", "B) ID and password-based verification", "C) 2-factor authentication", "D) Switching off the phone", 4),
    ("When ____ and ____ are in charge of data, the integrity of the data is imperiled?", "A) Access control, file deletion", "B) Network, file permission", "C) Access control, file permission", "D) Network, system", 3),
    ("The authenticity and security of data traveling over a network are ensured by?", "A) Firewall", "B) Antivirus", "C) Pentesting Tools", "D) Network-security protocols", 4),
    ("_________ creates an isolated passage across a public network that enables computing devices to communicate and receive data discreetly as though they were directly linked to the private network.", "A) Visual Private Network", "B) Virtual Protocol Network", "C) Virtual Protocol Networking", "D) Virtual Private Network", 4),
    ("___________ is one of the safest Linux operating systems, offering invisibility and an incognito mode to protect user data.", "A) Fedora", "B) Tails", "C) Ubuntu", "D) OpenSUSE", 2),
    ("What is a single entrance for multiple connectivities called?", "A) Web services", "B) Phishing", "C) Directory service", "D) Worms", 3),
    ("Circuit-level gateway firewalls have which of the below disadvantages?", "A) They are expensive", "B) They are complex in architecture", "C) They do not filter individual packets", "D) They are complex to set up", 3),
    ("The initial phase of ethical hacking is?", "A) DNS poisoning", "B) Footprinting", "C) ARP-poisoning", "D) Enumeration", 2),
    ("Which of the below can be classified as a type of computer threat?", "A) Dos Attack", "B) Phishing", "C) Soliciting", "D) Both 1 & 3", 1),
    ("In system hacking, which of the below is the most crucial activity?", "A) Information gathering", "B) Covering tracks", "C) Cracking passwords", "D) None of the above", 1),
    ("When the number of users surpasses the network capacity, which of the below network factors suffers the most?", "A) Reliability", "B) Performance", "C) Security", "D) Longevity", 2),
    ("Which of the below cyber security principles states that the security system should be as compact and straightforward as possible?", "A) Open-design", "B) The economy of the mechanism", "C) Least privilege", "D) Fail-safe defaults", 2),
    ("Which of the below malware types permits the hackers to access administrative controls and do nearly everything they want with the infected systems?", "A) RATs", "B) Worms", "C) Rootkits", "D) Botnets", 1),
    ("When any IT device, service, or system requires security checks, the term “security testing” is employed.?", "A) Threat", "B) Vulnerability", "C) Objective of evaluation", "D) Attack", 3),
    ("Which of the below is used to analyze network flow and monitor traffic?", "A) Managed detection and response", "B) Cloud access security broker", "C) Network traffic analysis", "D) None of the above", 3),
    ("Which of the below is a method of gaining access to a computer program or an entire computer system while circumventing all security measures?", "A) Backdoor", "B) Masquerading", "C) Phishing", "D) Trojan Horse", 1),
    ]

    selected_questions = random.sample(questions, 10)
    current_question = 0
    score = 0

    def next_question():
        nonlocal current_question
        if current_question < 10:
            question, *options, correct_option = selected_questions[current_question]
            current_question += 1

            question_label.config(text=f"Question {current_question}: {question}")
            option1_button.config(text=options[0], command=lambda: check_answer(1, correct_option))
            option2_button.config(text=options[1], command=lambda: check_answer(2, correct_option))
            option3_button.config(text=options[2], command=lambda: check_answer(3, correct_option))
            option4_button.config(text=options[3], command=lambda: check_answer(4, correct_option))
        # Update grid layout
            option1_button.grid(row=1, column=0, padx=3, pady=5, sticky="ew")
            option2_button.grid(row=1, column=1, padx=3, pady=5, sticky="ew")
            option3_button.grid(row=2, column=0, padx=3, pady=5, sticky="ew")
            option4_button.grid(row=2, column=1, padx=3, pady=5, sticky="ew")

        else:
            messagebox.showinfo("Quiz Complete", f"Quiz complete! Your score: {score}/10")
            show_home()

    def check_answer(selected_option, correct_option):
        nonlocal score
        if selected_option == correct_option:
            messagebox.showinfo("Correct", "Congratulations! You answered correctly.")
            score += 1
        else:
            correct_answer = ["A", "B", "C", "D"][correct_option - 1]
            messagebox.showinfo("Incorrect", f"Sorry, that's incorrect. The correct answer was {correct_answer}.")
        next_question()

    next_question()

# Function to show information in Info Guide
def show_info_guide():
    home_frame.pack_forget()
    puzzle_frame.pack_forget()
    quiz_frame.pack_forget()
    info_guide_frame.pack(fill='both', expand=True)

# Function to create the home page
def show_home():
    puzzle_frame.pack_forget()
    quiz_frame.pack_forget()
    info_guide_frame.pack_forget()
    home_frame.pack(fill='both', expand=True)

# Main GUI window
root = tk.Tk()
root.title("Cybersecurity App")
root.geometry("400x800")  # Adjusted height for better fitting on mobile screens
root.configure(bg="#0a0e27")

# Add background image to the main window
bg_image = tk.PhotoImage(file="image.gif")  # Main window background image
bg_label = tk.Label(root, image=bg_image)
bg_label.place(relwidth=1, relheight=1)

# Styling variables
button_bg = "#1e90ff"
button_fg = "#ffffff"
button_font = ("Helvetica", 14, "bold")  # Reduced font size for better mobile compatibility
label_font = ("Helvetica", 16, "bold")
info_font = ("Helvetica", 14)

# Home page
home_frame = tk.Frame(root, bg="#0a0e27")
home_bg = tk.PhotoImage(file="image.gif")  # Puzzle background image
home_bg_label = tk.Label(home_frame, image=home_bg)
home_bg_label.place(relwidth=1, relheight=1)
home_frame.pack(fill='both', expand=True)

welcome_label = tk.Label(home_frame, text="SECURE MINDS", font=label_font, fg=button_fg, bg="#0a0e27", wraplength=350)
welcome_label.pack(pady=20)

button_frame = tk.Frame(home_frame, bg="#0a0e27")
button_frame.pack(pady=20)

password_puzzle_button = tk.Button(button_frame, text="Password Puzzle", command=start_password_puzzle, font=button_font, width=15, height=2, bg=button_bg, fg=button_fg, bd=0)
password_puzzle_button.grid(row=1, column=1, padx=10, pady=10)

quiz_button = tk.Button(button_frame, text="Quiz", command=start_quiz, font=button_font, width=15, height=2, bg=button_bg, fg=button_fg, bd=0)
quiz_button.grid(row=2, column=1, padx=10, pady=10)

info_guide_button = tk.Button(button_frame, text="Info Guide", command=show_info_guide, font=button_font, width=15, height=2, bg=button_bg, fg=button_fg, bd=0)
info_guide_button.grid(row=3, column=1, padx=10, pady=10)

description_label = tk.Label(home_frame, text="This application provides interactive tools to test your cybersecurity knowledge and practice secure password creation.", font=info_font, fg=button_fg, bg="#0a0e27", wraplength=350, justify='center')
description_label.pack(side='bottom', pady=10)

# Password puzzle frame
puzzle_frame = tk.Frame(root, bg="#0a0e27")
puzzle_bg = tk.PhotoImage(file="image.gif")  # Puzzle background image
puzzle_bg_label = tk.Label(puzzle_frame, image=puzzle_bg)
puzzle_bg_label.place(relwidth=1, relheight=1)

level_label = tk.Label(puzzle_frame, text="", font=label_font, fg=button_fg, bg="#0a0e27")
level_label.pack(pady=10)

sample_chars = tk.StringVar()
sample_label = tk.Label(puzzle_frame, textvariable=sample_chars, font=info_font, fg=button_fg, bg="#0a0e27")
sample_label.pack(pady=5)

password_entry = tk.Entry(puzzle_frame, font=info_font, show="*", width=20)
password_entry.pack(pady=5)

submit_button = tk.Button(puzzle_frame, text="Submit", font=button_font, width=10, bg=button_bg, fg=button_fg, bd=0)
submit_button.pack(pady=10)

result_label = tk.Label(puzzle_frame, text="", font=info_font, fg=button_fg, bg="#0a0e27")
result_label.pack(pady=5)

go_home_button = tk.Button(puzzle_frame, text="Back to Home", command=show_home, font=button_font, width=15, bg=button_bg, fg=button_fg, bd=0)
go_home_button.pack(pady=10)

description_label = tk.Label(puzzle_frame, text="In this section you need to create a strong password based on the characters given to you.", font=info_font, fg=button_fg, bg="#0a0e27", wraplength=350, justify='center')
description_label.pack(side='bottom', pady=10)

# Quiz frame
quiz_frame = tk.Frame(root, bg="#0a0e27")
quiz_bg = tk.PhotoImage(file="image.gif")  # Quiz background image
quiz_bg_label = tk.Label(quiz_frame, image=quiz_bg)
quiz_bg_label.place(relwidth=1, relheight=1)


question_label = tk.Label(quiz_frame, text="", font=label_font, fg=button_fg, bg="#0a0e27", wraplength=350 )
question_label.grid(row=0, column=0, columnspan=2, pady=20)



# Create buttons with fixed width and wraplength
button_width = 15  # Adjust this width as needed
wrap_length = 150  # Adjust this wraplength as needed

option1_button = tk.Button(quiz_frame, text="", font=button_font, wraplength=150, width=15, height=3, bg=button_bg, fg=button_fg, bd=0)
option2_button = tk.Button(quiz_frame, text="", font=button_font, wraplength=150, width=15, height=3, bg=button_bg, fg=button_fg, bd=0)
option3_button = tk.Button(quiz_frame, text="", font=button_font, wraplength=150, width=15, height=3, bg=button_bg, fg=button_fg, bd=0)
option4_button = tk.Button(quiz_frame, text="", font=button_font, wraplength=150, width=15, height=3, bg=button_bg, fg=button_fg, bd=0)


go_home_button = tk.Button(quiz_frame, text="Back to Home", command=show_home, font=button_font, width=15, bg=button_bg, fg=button_fg, bd=0)
go_home_button.grid(row=3, column=0, columnspan=2, pady=10)

# Configure grid
quiz_frame.grid_rowconfigure(0, weight=0)
quiz_frame.grid_rowconfigure(1, weight=0)
quiz_frame.grid_rowconfigure(2, weight=0)
quiz_frame.grid_columnconfigure(0, weight=0)
quiz_frame.grid_columnconfigure(1, weight=0)

# Info Guide frame with scrollbar
info_guide_frame = tk.Frame(root, bg="#0a0e27")
info_guide_frame_bg = tk.PhotoImage(file="image.gif")  # Info guide background image
canvas = tk.Canvas(info_guide_frame, bg="#0a0e27")
scrollbar = tk.Scrollbar(info_guide_frame, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas, bg="#0a0e27")

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(
        scrollregion=canvas.bbox("all")
    )
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

info_label = tk.Label(scrollable_frame, text="""
Cyber-Security : 
                       
Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks. These cyberattacks are usually aimed at accessing, changing, or destroying sensitive information; extorting money from users through ransomware; or interrupting normal business processes.
Methods for Cyber-security are listed below :
                    
1.Strong Password:
Definition: A password that is difficult to guess or crack, usually incorporating a mix of letters, numbers, and special characters.
Example: Pa$$w0rd!
                      
2.Firewall:
Definition: A security system designed to prevent unauthorized access to or from a private network by filtering incoming and outgoing traffic based on security rules.
Example: A software firewall that blocks unauthorized internet connections
                      
3.Encryption:
Definition: A method of converting data into a code to prevent unauthorized access, ensuring that only authorized users can read the data.
Example: Encrypting sensitive information with a key.
                      
4.Two-Factor Authentication (2FA):
Definition: An extra layer of security where users must provide two forms of identification before gaining access to an account or system.
Example: A combination of a password and a text message code.
                      
5.Identifying Phishing Emails:
Guideline: Check the grammar and spelling of the email for errors, as phishing emails often contain mistakes.
Example: Noticing poor grammar in an email claiming to be from a bank.
                      
6.Cyber Security Protection:
Definition: Measures and technologies used to protect devices and networks from various cyber threats.
Example: Antivirus software that scans and removes malware
                      
7.Types of Cyber Security:
Definition: Various forms of security to protect different aspects of digital information.
Example: Cloud Security.
                      
8.False Benefit of Cyber Security:
Definition: Cybersecurity does not inherently cause system slowdown; it should improve overall security and efficiency.
Example: Providing privacy to users.
                      
9.Weakest Security Encryption Standard:
Definition: WEP (Wired Equivalent Privacy) is considered outdated and less secure compared to newer standards.
Example: WEP.
                      
10.Data Leakage Reduction:
Definition: Cryptography helps secure data from unauthorized access and leakage.
Example: Encrypting sensitive documents.
                      
11.Information Security Policy:
Definition: The CIA Triad (Confidentiality, Integrity, Availability) guides information security policies.
Example: CIA Triad.
                      
12.Data Security from Tampering:
Definition: Integrity ensures data is protected from unauthorized modification.
Example: Using hash functions to verify data integrity.
                      
13.Safeguarding Privacy:
Definition: Effective privacy protection involves more than just switching off devices; it includes using strong authentication methods.
Example: Two-factor authentication.
                      
14.Integrity of Data:
Definition: Access control and file permission issues can compromise data integrity.
Example: Setting appropriate permissions to prevent unauthorized file changes.
                      
15.Data Authenticity and Security:
Definition: Network-security protocols ensure data integrity and security over a network.
Example: Using SSL/TLS for secure communications.
                      
16.solated Passage Across a Public Network:
Definition: Virtual Private Network (VPN) creates a secure connection over a public network.
Example: VPN.

17.Safe Linux Operating System:
Definition: Tails is known for its focus on anonymity and data protection.
Example: Tails.
                      
18.Cyber Security Principle:
Definition: The economy of the mechanism states that security systems should be as simple as possible.
Example: Designing a straightforward security protocol.
                      
19.Security Testing Definition:
Definition: Objective of evaluation involves assessing the security of IT devices, services, or systems.
Example: Conducting penetration testing on a network.
                      
20.Network Flow and Traffic Monitoring:
Definition: Network traffic analysis helps in monitoring and analyzing network flow.
Example: Using network analysis tools to monitor traffic patterns.

Cyber-Threats & affects of it: 
                      
1.Phishing
Definition: A fraudulent attempt to obtain sensitive information by disguising oneself as a trustworthy entity in electronic communications.
Example: An email pretending to be from a bank asking for account details.
                      
2.Malware
Definition: Malicious software designed to harm, exploit, or otherwise compromise a computer or network.
Example: A computer virus.
                      
3.Spyware
Definition: Software that secretly monitors and collects user information or activities without the user’s consent.
Example: Keylogger software that records keystrokes.
                      
4.Trojan Horse
Definition: A type of malicious software that disguises itself as legitimate software to trick users into installing it, which then performs harmful actions.
Example: A fake antivirus program that installs malware.
                      
5.Ransomware
Definition: A type of malware that encrypts a user’s data and demands payment to restore access to it.
Example: A ransomware attack that locks files and demands cryptocurrency payment.
                      
6.Hacking Technique
Definition: Pharming involves redirecting users to fake websites to deceive them and obtain sensitive information.
Example: Redirecting users from a legitimate bank site to a fraudulent one.

                       
7.Method for IP Address Gain
Definition: Websites often track IP addresses when users visit them.
Example: A website logs the IP addresses of its visitors.
                      
8.Peer-to-Peer Cybercrime
Definition: Cybercrimes that involve direct interactions between users.
Example: Phishing attacks conducted via email.
                      
9.Internet Fraud
Definition: Phishing attack where users are tricked into revealing personal data.
Example: An email asking for login credentials.
                      
10.Initial Phase of Ethical Hacking
Definition: Footprinting involves gathering information about a target system.
Example: Collecting domain information from a target.

11.Disadvantage of Circuit-Level Gateway Firewalls
Definition: They do not filter individual packets, which can limit security.
Example: Circuit-level gateways.
                      
12.Type of Computer Threat:
Definition: Dos Attack and Phishing are types of computer threats.
Example: Dos Attack.
                      
13.Malware Type Allowing Administrative Controls
Definition: RATs (Remote Access Trojans) provide extensive control over infected systems.
Example: A RAT that allows remote control of a compromised computer.

14.Access to Computer System Circumventing Security
Definition: Backdoor allows unauthorized access to a computer system by bypassing normal authentication processes.
Example: A hidden login feature installed by malware.
                      
15.Botnet:
Definition: A network of computers infected with malware and controlled by a cybercriminal, often used to launch attacks or distribute spam.
Example: Computers used in distributed denial-of-service (DDoS) attacks.
                      
16.Non-Cybercrime:
Definition: Advanced Encryption Standard (AES) is a security standard, not a cybercrime.
Example: Phishing.
                      

17.Network Factor Affected by User Overload:
Definition: Performance suffers when network capacity is exceeded.
Example: Network slowdown due to too many users
""", 
font=info_font, fg=button_fg, bg="#0a0e27", wraplength=350)
info_label.pack(pady=10)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

go_home_button = tk.Button(scrollable_frame,  text="Back to Home", command=show_home, font=button_font, width=15, bg=button_bg, fg=button_fg, bd=0)
go_home_button.pack(pady=10)

# Start with the home page
show_home()

root.mainloop()
