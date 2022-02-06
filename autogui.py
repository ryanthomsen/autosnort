#!/usr/bin/env python3
#This is the GUI for autosnort
#File in its entireity by Ryan Thomsen

import tkinter as tk
import tkinter.font as font
from tkinter.constants import BOTTOM, END, HORIZONTAL, LEFT, RAISED, RIGHT, SUNKEN
from tkinter import filedialog as fd
from autorule import *
import os

#Bools for tracking what mode the gui is in
global TOGGLE
TOGGLE = False #Bool for determining whether the snort button is currently pressed down or not
global SNIFFING
SNIFFING = False #Bool for determining whether we are using a preset pcap or listening on current network
global curr_pcap
curr_pcap = "" #String tracker for current pcap filename

#Function to display rules in the display window
#Takes in a list of snort rules, the number of occurences, The SID num
#to start with from config. a list of packets, and the bool from config
#determining whether or not printing all packets is desired
def display_rules(snort_rules, occurences, SID_START, packet_list, PRINTPCKT):
  #Prints packets if option is enabled in config
  if(PRINTPCKT):
    for packet in packet_list:
        packet = str(packet)
        update_display(packet)
    update_display("\n")
  #Prints rules from Snort Rules as well as their occurences in a format
  #that can be directly copied and pasted into snort
  update_display("Snort Rule Suggestions: ")
  for index in range(0, len(snort_rules), 1):
    string1 = snort_rules[index] + ":" + str(SID_START) + ";)"
    update_display(string1)
    SID_START += 1
    string1= "# of Packets Flagged:" + str(occurences[index]) + "\n______________________________________________\n"
    update_display(string1)

#Function controlling the actions of the main snort button in the gui
def snort_button_method():
    global curr_pcap
    global TOGGLE
    ###IF Button is currently raised (i.e. toggle is true)
    if(TOGGLE):
        TOGGLE = False
        #If in listening mode, set button to listen graphic
        if(not not_listening):
            snortbutton.configure(background="turquoise2", relief=RAISED, text = "Listen")
        #If not in Listening Mode, set button to pcap mode grapphic
        else:
            snortbutton.configure(background="green", relief=RAISED, text = "Autosnort")
        update_display("Traffic has been closed.")

    ###IF Button is currently lowered.. i.e. toggle is false
    else:
        #If in listen mode
        if(not not_listening):
            curr_pcap = listen4pigs(slider.get()) #run listen method from autosnort to create a pcap
            tupleout = run_pcap(curr_pcap) #run rule generator with newly generated pcap
            #Assign vars from Tuple
            snort_rules = tupleout[0]
            occurences = tupleout[1]
            SID_START = tupleout[2]
            packet_list = tupleout[3]
            PRINTPCKT = tupleout[4]
            #Displauys rules to window
            display_rules( snort_rules, occurences, SID_START, packet_list, PRINTPCKT)
        #If not in listen mode
        elif(not_listening):
            #Check to see if a pcap has been selected, denies if no file has been chosen
            if(len(curr_pcap) < 1):
                update_display("Please choose and open a file at the bottom.")
            #IF a pcap has been selected
            else:
                tupleout = run_pcap(curr_pcap) #Runs pcap through autosnort
                #Assigns variables from outputted tuple
                snort_rules = tupleout[0]
                occurences = tupleout[1]
                SID_START = tupleout[2]
                packet_list = tupleout[3]
                PRINTPCKT = tupleout[4]
                #Displays rules to window
                display_rules( snort_rules, occurences, SID_START, packet_list, PRINTPCKT)
        #Resets variables after display
        tupleout = ''
        snort_rules = ''
        occurences = ''
        SID_START = ''
        packet_list = ''
        PRINTPCKT = ''
        #Toggles button
        TOGGLE = True
        #Toggles button display
        snortbutton.configure(background="red", relief=SUNKEN, text="Close")



#Function to Open the config.txt file
def open_conf():
    config_name = "config.txt"
    os.system(config_name)

#Function to update display window with text
def update_display(text):
    display_win.insert(END, text)
    display_win.insert(END, "\n")

#Function to toggle between light and dark mode
def light_controller():
    global dark_mode
    dark_mode = not dark_mode
    if dark_mode:
        display_win.configure(fg='white',bg='black')
    else:
        display_win.configure(fg='black', bg='white')

#Function to choose pcap file and assign appropriate file path
#Opens in default file manager window for user's operating system for selection
def choose_file():
    file_name=tk.filedialog.askopenfilename(initialdir="autosnort", title="Select a pcap file or a pigget txt file", filetypes =[("pcap", ".pcap"),
                                                                                                                                 ("pcapng",".pcapng"),
                                                                                                                                 ("pigget", ".txt")])
    if file_name!="":
        filename_input.delete(0,END)
        filename_input.insert(0,str(file_name))

#Opens pcap file if not in listening mode
def open_file():
    global not_listening
    if not_listening == False:
        update_display("Cannot open files in Listening Mode.")
    else:
        file_name = filename_input.get()
        if(file_name[-4:len(file_name)] == "pcap" or file_name[-6:len(file_name)] == "pcapng"):
            update_display("The pcap " + file_name + " has been opened.")
        #If file exists reads pcap
        if os.path.isfile(file_name):
          global curr_pcap
          curr_pcap = rdpcap(file_name)
        #If file doesnt exist throws error message
        else:
          str = "Error:" + file_name + "doesn't not exist."
          update_display(str)
        #Planned functionality for custom packet files from pigget
        #if(file_name[-3:len(file_name)] == "txt"):
        #    update_display("The pigget file " + file_name + " has been opened.")    
        
#Function to switch between listen mode and pcap mode
def switch_listen():
    global not_listening
    not_listening = not not_listening
    #If in listening mode
    if(not not_listening and TOGGLE==False):
        snortbutton.configure(background="turquoise2", relief=RAISED, text = "Listen")
    elif TOGGLE==False and not_listening:
        snortbutton.configure(background="green", relief=RAISED, text = "Autosnort")
    elif TOGGLE:
        snort_button_method()

#Funciton to Load GUI window using Tkinter
def load_GUI():
    ###Create Main Window###
    global root
    root = tk.Tk()
    root.title('Autosnort')
    root.geometry('1080x720')
    #Set initial mode using bools
    global dark_mode
    dark_mode = tk.IntVar(root, 1)
    global not_listening
    not_listening = tk.IntVar(root, 0)

    #Image Setup
    conf_img = tk.PhotoImage(file="Icons/conf.png")
    #green_img = tk.PhotoImage(file="Icons/greenbutton2.png")
    #red_img = tk.PhotoImage(file="Icons/redbutton2.png")
    filler_img = tk.PhotoImage(file="Icons/filler_img.png")
    auto_snort_img = tk.PhotoImage(file="Icons/autosnort.png")
    listen_img = tk.PhotoImage(file="Icons/listen.png")
    quit_img = tk.PhotoImage(file="Icons/quit.png")
    light_img = tk.PhotoImage(file="Icons/light.png")
    root.iconphoto(False, auto_snort_img)

    ###Create Main Containers###
    global rt_frame
    rt_frame = tk.Frame(    root, 
                            bg='grey60', 
                            pady=10,
                            padx=10
                            )
    global left_frame
    left_frame = tk.Frame(  root,
                            bg='grey60',
                            pady=3,
                            )

    ###Container Layout###
    #Configure window stretching
    root.grid_rowconfigure(0, weight = 1)
    root.grid_columnconfigure(0, weight = 1)
    root.grid_columnconfigure(1, weight = 4)


    #Configure Grid Placement
    left_frame.grid(row=0, column=0, sticky ="nsew")
    rt_frame.grid(row=0, column=1, sticky = "nsew")

    ###Font Setup###
    oink_font = font.Font(size=25)
    output_font = font.Font(size=15)
    butt_font = font.Font(family='Helvetica', size = 14, weight='bold')
    bott_font = font.Font(size=13)



    ###Widget Setup###

    #Top_Frame Widgets
    #Quit Button (Always Important)
    global quit_button
    quit_button = tk.Button(    left_frame,
                                image= quit_img,
                                relief=RAISED,
                                text="Exit",
                                compound="top",
                                font=butt_font,
                                activebackground="blue",
                                height=120,
                                fg="black",
                                background="grey",
                                command=quit
                                )
    #Dark_Mode
    global dark_button
    dark_button = tk.Checkbutton(left_frame,
                                    text="Dark Mode",
                                    relief=RAISED,
                                    image=light_img,
                                    compound="top",
                                    font=butt_font,
                                    fg="black",
                                    activebackground="blue",
                                    background="grey",
                                    height=120,
                                    #width=100,
                                    variable=dark_mode,
                                    command=light_controller)
    #Config Button
    global conf_button
    conf_button = tk.Button(    left_frame,
                                relief=RAISED,
                                text = "Settings",
                                font=butt_font,
                                compound="top",
                                fg="black",
                                activebackground="blue",
                                image= conf_img,
                                height=120,
                                background="grey",
                                command=open_conf
                                )

    #CheckBox
    global hear_check
    hear_check = tk.Checkbutton(left_frame,
                                text="Listen Mode",
                                relief=RAISED,
                                image=listen_img,
                                compound="top",
                                font=butt_font,
                                fg="black",
                                activebackground="blue",
                                background="grey",
                                height=120,
                                #width=150,
                                #variable=not_listening,
                                command=switch_listen)

    #Listen Time Slider
    global slider
    slider = tk.Scale(          rt_frame,
                                label="# of Packets to Listen for:",
                                from_=100,
                                to=10000,
                                orient=HORIZONTAL
                                )

    #Run AutoSnort Button
    global snortbutton
    snortbutton = tk.Button(    left_frame,

                                activebackground ="blue",
                                background = "green",
                                relief=RAISED,
                                text="Autosnort",
                                bd = "10",
                                compound="top",
                                width=800,
                                font = oink_font,
                                image = auto_snort_img,
                                command = snort_button_method
                                )



    #Right_Frame
    global display_scrollbar
    display_scrollbar = tk.Scrollbar(rt_frame,
                                    bg = "grey"
                                    )
    #Displau Window and scrollbar
    global display_win
    display_win=tk.Text(        rt_frame,
                                background="black",
                                font=output_font,
                                fg="white",
                                yscrollcommand=display_scrollbar.set
                                )
    display_scrollbar.config(command=display_win.yview)


    #Fileinput Field
    global filename_input
    filename_input = tk.Entry(  left_frame,
                                background="lightsteelblue3",
                                font=output_font
                                )
    #Console Input field
    global console_input
    console_input = tk.Entry(   rt_frame,
                                background="lightsteelblue3",
                                font=output_font
                                )
    #Button to Open File
    global open_file_button
    open_file_button = tk.Button(left_frame,
                                background="grey90",
                                relief=RAISED,
                                activebackground="blue",
                                image=filler_img,
                                font=bott_font,
                                text="Open File",
                                compound="c",
                                command=open_file
                                )
    #Button to Choose File
    global choose_file_button
    choose_file_button = tk.Button(left_frame,
                                background="grey90",
                                relief=RAISED,
                                activebackground="blue",
                                image=filler_img,
                                font=bott_font,
                                text="Choose File",
                                compound="c",
                                command=choose_file
                                )



    #Configure Rows & columns for right frame
    rt_frame.grid_rowconfigure(0, weight=0)
    rt_frame.grid_rowconfigure(1, weight=1)
    rt_frame.grid_rowconfigure(2, weight=0)


    rt_frame.grid_columnconfigure(0, weight=1)

    #Configure Rows and columns for left frame
    left_frame.grid_rowconfigure(0, weight=0)
    left_frame.grid_rowconfigure(1, weight=1)
    left_frame.grid_rowconfigure(2, weight=0)


    left_frame.grid_columnconfigure(0, weight=1)
    left_frame.grid_columnconfigure(1, weight=1)
    left_frame.grid_columnconfigure(2, weight=1)
    left_frame.grid_columnconfigure(3, weight=1)


    #Layout Widgets
    #rt_frame
    slider.grid(row=0, column=0, sticky="we")
    display_scrollbar.grid(row=1, column=1, sticky="ns")
    display_win.grid(row=1, column=0, sticky="NSEW")
    display_win.grid_columnconfigure(0, weight=1)
    display_win.grid_rowconfigure(0, weight=1)
    update_display("Welcome to Austosnort!\nThis will serve as the Display Window.\nProject by Ryan Thomsen and Matt Ages")
    console_input.grid(row=2, column=0, sticky="ew", columnspan=2)


    #left_frame
    #Row1
    hear_check.grid(row=0, column=0, sticky="WE")
    conf_button.grid(row=0, column=2, sticky="WE")
    quit_button.grid(row=0, column=3, sticky="WE")
    dark_button.grid(row=0, column=1, sticky="WE")

    #Row2
    snortbutton.grid(row=1, column=0, sticky="NSEW", columnspan=4)

    #Row3
    filename_input.grid(row=2, column=0, columnspan=2, sticky="WE")
    filename_input.grid_columnconfigure(0, weight=1)
    choose_file_button.grid(row=2, column=2, sticky="WE")
    choose_file_button.grid_columnconfigure(0, weight=0)
    open_file_button.grid(row=2, column=3, sticky="WE")
    open_file_button.grid_columnconfigure(0, weight=0)
    root.mainloop()