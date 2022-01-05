#!/usr/bin/env python3

import tkinter as tk
import tkinter.font as font
from tkinter.constants import BOTTOM, END, HORIZONTAL, LEFT, RAISED, RIGHT, SUNKEN
from tkinter import filedialog as fd
import os

#Bools
TOGGLE = False
SNIFFING = False
#Method to write to display terminal
def write_slogan():
    global TOGGLE




    ###IF Button is currently pressed
    if(TOGGLE):
        #snortbutton.configure(image = red_img)
        TOGGLE = False
        snortbutton.configure(background="green", relief=RAISED)
        if listen_bool:
            #Replace with way to stop sniffing
            x = 5


    ###IF Button is currently RAISED
    else:
        #snortbutton.configure(image = green_img)
        TOGGLE = True
        snortbutton.configure(background="red", relief=SUNKEN)
        if listen_bool:
            #Replace with way to start sniffing
            x = 5
    update_display("Tkinter is easy to use!")

#Method to Open the config.txt file
def open_conf():
    config_name = "config.txt"
    os.system(config_name)

def update_display(text):
    display_win.insert(END, text + "\n")

def light_controller():
    global dark_mode
    dark_mode = not dark_mode
    if dark_mode:
        display_win.configure(fg='white',bg='black')
    else:
        display_win.configure(fg='black', bg='white')

def choose_file():
    file_name=tk.filedialog.askopenfilename()
    filename_input.delete(0,END)
    filename_input.insert(0,str(file_name))

def open_file():
    file_name = filename_input.get()
    update_display("The file path " + file_name + "has been opened.")


###Create Main Window###
root = tk.Tk()
root.title('Autosnort')
root.geometry('1080x720')
dark_mode = tk.IntVar(root, 1)
listen_bool = tk.IntVar(root)


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
rt_frame = tk.Frame(    root, 
                        bg='grey60', 
                        pady=10,
                        padx=10
                        )
left_frame = tk.Frame(  root,
                        bg='grey60',
                        pady=3,
                        )

###Container Layout###
#Configure window stretching
root.grid_rowconfigure(0, weight = 1)
root.grid_columnconfigure(0, weight = 1)
root.grid_columnconfigure(1, weight = 1)


#Configure Grid Placement
left_frame.grid(row=0, column=0, sticky ="nsew")
rt_frame.grid(row=0, column=1, sticky = "nsew")

###Font Setup###
oink_font = font.Font(size=25)
output_font = font.Font(size=15, )
butt_font = font.Font(family='Helvetica', size = 14, weight='bold')



###Widget Setup###

#Top_Frame Widgets
#Quit Button (Always Important)
quit_button = tk.Button(    left_frame,
                            image= quit_img,
                            text="Exit",
                            compound="top",
                            font=butt_font,
                            height=120,
                            fg="black",
                            background="grey",
                            command=quit
                            )
#Dark_Mode
dark_button = tk.Checkbutton(left_frame,
                                 text="Dark Mode",
                                 image=light_img,
                                 compound="top",
                                 font=butt_font,
                                 fg="black",
                                 background="grey",
                                 height=120,
                                 #width=100,
                                 variable=dark_mode,
                                 command=light_controller)
#Config Button
conf_button = tk.Button(    left_frame,
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
hear_check = tk.Checkbutton(left_frame,
                            text="Listen Mode",
                            image=listen_img,
                            compound="top",
                            font=butt_font,
                            fg="black",
                            background="grey",
                            height=120,
                            #width=150,
                            variable=listen_bool)

#Listen Time Slider
slider = tk.Scale(          rt_frame,
                            from_=60,
                            to=600,
                            orient=HORIZONTAL
                            )

#Run AutoSnort Button
global snortbutton
snortbutton = tk.Button(    left_frame,

                            activebackground ="blue",
                            background = "green",
                            relief=RAISED,
                            bd = "10",
                            width=800,
                            font = oink_font,
                            image = auto_snort_img,
                            command = write_slogan
                            )



#Right_Frame
global display_win
display_scrollbar = tk.Scrollbar(rt_frame,
                                bg = "grey"
                                )
display_win=tk.Text(rt_frame,
                                                     background="black",
                                                     font=output_font,
                                                     fg="white",
                                                     yscrollcommand=display_scrollbar.set
                                                     )
display_scrollbar.config(command=display_win.yview)




filename_input = tk.Entry(  left_frame,
                            background="grey",
                            font=output_font
                            )
console_input = tk.Entry(   rt_frame,
                            background="grey",
                            font=output_font
                            )

open_file_button = tk.Button(left_frame,
                            background="grey90",
                             activebackground="blue",
                            image=filler_img,
                            text="Open File",
                            compound="c",
                            height = 50,
                            width = 100,
                            command=open_file
                            )
choose_file_button = tk.Button(left_frame,
                               background="grey90",
                               activebackground="blue",
                               image=filler_img,
                               text="Choose File",
                               compound="c",
                               height=50,
                               width=100,
                               command=choose_file
                               )



#Configure Rows & columns rt
rt_frame.grid_rowconfigure(0, weight=0)
rt_frame.grid_rowconfigure(1, weight=1)
rt_frame.grid_rowconfigure(2, weight=0)


rt_frame.grid_columnconfigure(0, weight=1)

#Configure Rows and columns left
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
conf_button.grid(row=0, column=1, sticky="WE")
quit_button.grid(row=0, column=2, sticky="WE")
dark_button.grid(row=0, column=3, sticky="WE")

#Row2
snortbutton.grid(row=1, column=0, sticky="NSEW", columnspan=4)

#Row3
filename_input.grid(row=2, column=0, columnspan=2, sticky="WE")
choose_file_button.grid(row=2, column=2, sticky="E")
open_file_button.grid(row=2, column=3, sticky="E")



root.mainloop()
