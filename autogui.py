#!/usr/bin/env python3

import tkinter as tk
import tkinter.font as font
from tkinter.constants import BOTTOM, END, LEFT, RIGHT, TOP, NW, SW
import os

#Bools
TOGGLE = True

#Method to write to display terminal
def write_slogan():
    global TOGGLE
    global snortbutton
    if(TOGGLE):
        snortbutton.configure(image = red_img)
        TOGGLE = False
    else:
        snortbutton.configure(image = green_img)
        TOGGLE = True
    update_display("Tkinter is easy to use!")

#Method to Open the config.txt file
def open_conf():
    config_name = "config.txt"
    os.system(config_name)

def update_display(text):
    global display_win
    display_win.insert(END, text + "\n")


###Create Main Window###
root = tk.Tk()
root.title('Autosnort')
root.geometry('{}x{}'.format(200,300))


###Create Main Containers###
top_frame = tk.Frame(   root,
                        bg = 'cyan',
                        width =150,
                        height = 50,
                        pady = 3
                        )

center = tk.Frame(      root,
                        bg='purple',
                        width=150,
                        height=150,
                        pady = 3
                        )

btm_frame = tk.Frame(   root, 
                        bg='pink', 
                        width=300, 
                        height=50, 
                        pady=3
                        )

rt_frame = tk.Frame(    root, 
                        bg='green', 
                        width=150, 
                        height=50, 
                        pady=3
                        )


###Container Layout###
#Configure window stretching
root.grid_rowconfigure(0, weight = 0)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=0)
root.grid_columnconfigure(0, weight = 0)
root.grid_columnconfigure(1, weight = 1)


#Configure Grid Placement
top_frame.grid(row=0, sticky = "ew", columnspan = 2)
center.grid(row=1, column=0, sticky="nsew")
rt_frame.grid(row=1, column=1, sticky = "nsew", rowspan=2)
btm_frame.grid(row=2, sticky="ew")


###Font Setup###
oink_font = font.Font(size=25)
output_font = font.Font(size=15, )

#Image Setup
conf_img = tk.PhotoImage(file="Icons/conf.png")
green_img = tk.PhotoImage(file="Icons/greenbutton.png")
red_img = tk.PhotoImage(file="Icons/redbutton.png")
filler_img = tk.PhotoImage(file="Icons/filler_img.png")
auto_snort_img = tk.PhotoImage(file="Icons/autosnort.png")
root.iconphoto(False, auto_snort_img)


###Widget Setup###

#Top_Frame Widgets

#Autosnort Image
auto_snort = tk.Label(      top_frame,
                            image=auto_snort_img,
                            height=100,
                            width=100,
                            highlightbackground="white",
                            highlightthickness= 2,
                            background="black"
                            )

#Quit Button (Always Important)
quit_button = tk.Button(    top_frame,
                            image= filler_img,
                            text="Exit",
                            compound="c",
                            font=output_font,
                            height=100,
                            width=100,
                            fg="pink",
                            background="black",
                            highlightbackground="white",
                            highlightthickness=2,
                            command=quit
                            )

#Config Button
conf_button = tk.Button(    top_frame,
                            text = "Settings",
                            font=output_font,
                            compound="c",
                            fg="pink",
                            activebackground="grey",
                            image= conf_img,
                            background="black",
                            highlightbackground="white",
                            highlightthickness=2,
                            command=open_conf
                            )

#CheckBox
listening = tk.IntVar()
hear_check = tk.Checkbutton(top_frame,
                            text="Listen Mode",
                            image=filler_img,
                            compound="c",
                            font=output_font,
                            fg="pink",
                            background="black",
                            highlightbackground="white",
                            highlightthickness=2,
                            height=100,
                            width=100,
                            variable=listening)

#Layout Top Widgets
auto_snort.grid(row=0, column = 0)
hear_check.grid(row=0, column = 1)
conf_button.grid(row=0, column=2)
quit_button.grid(row=0, column=3)




#Center_Frame
#Run AutoSnort Button
global snortbutton
snortbutton = tk.Button(    center,
                            #height=10,
                            #width=20,
                            #text = ', ._\n@"_.)~\n!! !',
                            activebackground ="pink",
                            background = "grey",
                            bd = "4",
                            font = oink_font,
                            image = green_img,
                            command = write_slogan
                            )


#Listen Time Slider
slider = tk.Scale(          center, 
                            from_=60, 
                            to=600)

#Layout Top Widgets
snortbutton.grid(row=0, column=0)
slider.grid(row=0, column=1)



#Right_Frame
global display_win
display_win = tk.Text(      rt_frame,
                            background="yellow",
                            font = output_font,
                            fg = "black"
                            )

#Layout Top Widgets
display_win.grid(row=0, column=0)
display_win.grid_columnconfigure(0, weight = 1)
display_win.grid_rowconfigure(0, weight=1)
update_display("Welcome to Austosnort!\nThis will serve as the Display Window.\nProject by Ryan Thomsen and Matt Ages")


#Btm_Frame
filename_input = tk.Entry(  btm_frame,
                            background="grey")

#Layout Bottom Widgets
filename_input.grid(row=0, column=0)

root.mainloop()
